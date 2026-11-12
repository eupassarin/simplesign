using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES.Internal;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <content>
/// The two phases of a deferred CAdES signature: phase one stops after the signed attributes are built,
/// phase two starts from the signature made over them and runs the same steps as one-call signing.
/// </content>
public sealed partial class CadesSignerBuilder
{
    /// <summary>The baseline profile configured on this builder.</summary>
    internal AdesBaselineProfile Profile => _options.Profile;

    /// <summary>A builder that completes <paramref name="session"/>: its content, level and unsigned additions.</summary>
    internal static CadesSignerBuilder ForDeferredCompletion(CadesDeferredSession session)
    {
        var builder = new CadesSignerBuilder(session.Content, logger: null);
        return builder.With(builder._options with
        {
            Profile = DeferredProfile.Restore(
                session.RequestedLevel, session.LevelFailureBehavior, session.TimestampEndpoint,
                session.ArchiveTimestampEndpoint, session.RevocationPreference, session.ClockSkewSeconds),
            ContentType = session.Attached ? CadesContentType.Enveloped : CadesContentType.Detached,
            ExtendedForm = session.ExtendedForm,
            OperationId = session.OperationId,
        });
    }

    /// <summary>
    /// Phase one: checks the certificate, chain and algorithms against the signing policy, builds the signed
    /// attributes and returns them with the session. A refusal is recorded by the audit sink.
    /// </summary>
    internal async Task<CadesDeferredPrepareResult> PrepareDeferredAsync(byte[] sessionIntegrityKey, CancellationToken cancellationToken)
    {
        try
        {
            return await PrepareDeferredCoreAsync(sessionIntegrityKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (_options.AuditSink is not null && ex is not OperationCanceledException)
        {
            var refused = SignatureAuditEvent.Start(
                "CAdES", _options.OperationId, _options.Profile.Level, SignerCertificate, _options.SigningPolicy, _data);
            await _options.AuditSink.RecordAsync(
                refused with { Reason = (ex as SigningException)?.Reason, Message = ex.Message }, cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<CadesDeferredPrepareResult> PrepareDeferredCoreAsync(byte[] sessionIntegrityKey, CancellationToken cancellationToken)
    {
        var credential = _options.Credential
            ?? throw new SigningException(
                "Certificate is required. Call WithCertificate() before preparing a deferred signature.",
                SigningErrorReason.CredentialMissing);
        SigningStart start = await BeginAsync(credential, cancellationToken).ConfigureAwait(false);
        if (_options.ExtendedForm != CadesExtendedForm.None && _options.Profile.Timestamp is null)
        {
            throw new SigningException(
                "Extended validation data needs a signature timestamp: use WithLevel(AdesBaselineProfile.Timestamped(tsa)).",
                SigningErrorReason.LevelNotAchievable);
        }

        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;
        byte[] signedAttributes = BuildSignedAttributesToSign(start.Certificate, start.HashAlgorithm, signingTime, start.ContentTimestamp);
        var profile = _options.Profile;
        var session = new CadesDeferredSession
        {
            SignedAttributes = signedAttributes,
            Content = _data,
            Attached = _options.ContentType == CadesContentType.Enveloped,
            CertificateDer = start.Certificate.RawData,
            ExtraCertificatesDer = start.Chain.Count == 0 ? null : [.. start.Chain.Select(c => c.RawData)],
            HashAlgorithm = start.HashAlgorithm.Name!,
            SignatureAlgorithmOid = start.SignatureAlgorithmOid,
            SigningTime = signingTime,
            RequestedLevel = profile.Level,
            LevelFailureBehavior = profile.FailureBehavior,
            TimestampEndpoint = profile.Timestamp?.Endpoint.ToString(),
            ArchiveTimestampEndpoint = profile.ArchiveTimestamp?.Endpoint?.ToString(),
            RevocationPreference = profile.LongTermValidation?.RevocationPreference ?? RevocationPreference.OcspFirst,
            ClockSkewSeconds = DeferredProfile.ClockSkewSecondsToRecord(profile),
            ExtendedForm = _options.ExtendedForm,
            PolicyStoreAttribute = _options.PolicyStore is { } store ? CadesSignaturePolicyStore.Encode(store).DerValue : null,
            OperationId = _options.OperationId,
        };

        byte[] sessionData = session.Protect(sessionIntegrityKey);
        _options.Dependencies.Logger.DeferredPrepared(_options.OperationId ?? "-", signedAttributes.Length, sessionData.Length);
        return new CadesDeferredPrepareResult
        {
            DataToSign = signedAttributes,
            SessionData = sessionData,
            DigestAlgorithm = start.HashAlgorithm.Name!,
            SignatureAlgorithmOid = start.SignatureAlgorithmOid,
            Warnings = start.Warnings.AsReadOnly(),
            RsaPssParameters = start.RsaPssParameters,
            OperationId = _options.OperationId,
        };
    }

    /// <summary>
    /// Phase two: verifies <paramref name="rawSignature"/> against the certificate of the session, assembles the
    /// CMS and takes it to the requested level. The outcome, signed or refused, is recorded by the audit sink.
    /// </summary>
    internal async Task<CadesSigningResult> CompleteDeferredAsync(
        CadesDeferredSession session, byte[] rawSignature, CancellationToken cancellationToken)
    {
        using X509Certificate2 certificate = CertificateLoader.LoadCertificate(session.CertificateDer);
        List<X509Certificate2> chain = [.. (session.ExtraCertificatesDer ?? []).Select(CertificateLoader.LoadCertificate)];
        try
        {
            return await SignatureAudit.RunAsync(
                _options.AuditSink,
                () => SignatureAuditEvent.Start("CAdES", _options.OperationId, _options.Profile.Level, certificate, _options.SigningPolicy, _data),
                () => CompleteDeferredCoreAsync(session, rawSignature, certificate, chain, cancellationToken),
                result => (result.SignedArtifact, result.AchievedLevel),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach (X509Certificate2 extra in chain)
            {
                extra.Dispose();
            }
        }
    }

    private async Task<CadesSigningResult> CompleteDeferredCoreAsync(
        CadesDeferredSession session,
        byte[] rawSignature,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        ResolvedSigningAlgorithm algorithm = SigningAlgorithmResolver.Resolve(
            certificate, new HashAlgorithmName(session.HashAlgorithm), hashAlgorithmExplicitlySet: true, session.SignatureAlgorithmOid);
        if (!CmsSignatureBuilder.VerifyExternalSignature(
                session.SignedAttributes, rawSignature, certificate, algorithm.HashAlgorithm, algorithm.SignatureAlgorithmOid))
        {
            throw new SigningException(
                "The external signature does not verify with the certificate of the session.",
                SigningErrorReason.ExternalSignerReturnedInvalidSignature);
        }

        _options.Dependencies.Logger.DeferredCompleting(_options.OperationId ?? "-", rawSignature.Length);
        byte[] cms = CmsSignatureBuilder.BuildSignedData(
            CmsSignatureBuilder.GetDigestOid(algorithm.HashAlgorithm), algorithm.SignatureAlgorithmOid, algorithm.HashAlgorithm,
            session.SignedAttributes, rawSignature, certificate, [certificate, .. chain],
            eContent: session.Attached ? session.Content : null);

        // The policy store goes in before the timestamps, so an archive timestamp covers it.
        if (session.PolicyStoreAttribute is { } policyStore)
        {
            cms = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Create(Oids.SignaturePolicyStore, policyStore)]);
        }

        return await FinishAsync(cms, certificate, chain, algorithm.HashAlgorithm, [], stopwatch, cancellationToken).ConfigureAwait(false);
    }
}
