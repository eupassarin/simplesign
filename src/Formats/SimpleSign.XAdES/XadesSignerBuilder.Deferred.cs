using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES.Internal;

namespace SimpleSign.XAdES;

/// <content>
/// The two phases of a deferred XAdES signature: phase one stops after the document is assembled with an
/// empty ds:SignatureValue, phase two writes the signature made over the canonical SignedInfo and runs the
/// same steps as one-call signing.
/// </content>
public sealed partial class XadesSignerBuilder
{
    /// <summary>The baseline profile configured on this builder.</summary>
    internal AdesBaselineProfile Profile => _options.Profile;

    /// <summary>A builder that completes <paramref name="session"/>: its detached data, level and extended form.</summary>
    internal static XadesSignerBuilder ForDeferredCompletion(XadesDeferredSession session)
    {
        var builder = new XadesSignerBuilder(session.DetachedContent ?? [], logger: null);
        return builder.With(builder._options with
        {
            Profile = DeferredProfile.Restore(
                session.RequestedLevel, session.LevelFailureBehavior, session.TimestampEndpoint,
                session.ArchiveTimestampEndpoint, session.RevocationPreference, session.ClockSkewSeconds),
            ExtendedForm = session.ExtendedForm,
            OperationId = session.OperationId,
            AdditionalDataObjects = session.ExternalDataObjects is { Length: > 0 } external
                ? [.. external.Select(o => XadesDataObject.External(o.Uri, o.Content))]
                : null,
        });
    }

    /// <summary>
    /// Phase one: checks the certificate, chain and algorithms against the signing policy, assembles the
    /// document with an empty signature value and returns the canonical SignedInfo with the session. A refusal
    /// is recorded by the audit sink.
    /// </summary>
    internal async Task<XadesDeferredPrepareResult> PrepareDeferredAsync(byte[] sessionIntegrityKey, CancellationToken cancellationToken)
    {
        try
        {
            return await PrepareDeferredCoreAsync(sessionIntegrityKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (_options.AuditSink is not null && ex is not OperationCanceledException)
        {
            var refused = SignatureAuditEvent.Start(
                "XAdES", _options.OperationId, _options.Profile.Level, SignerCertificate, _options.SigningPolicy, _xmlData);
            await _options.AuditSink.RecordAsync(
                refused with { Reason = (ex as SigningException)?.Reason, Message = ex.Message }, cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<XadesDeferredPrepareResult> PrepareDeferredCoreAsync(byte[] sessionIntegrityKey, CancellationToken cancellationToken)
    {
        var credential = _options.Credential
            ?? throw new SigningException(
                "Certificate is required. Call WithCertificate() before preparing a deferred signature.",
                SigningErrorReason.CredentialMissing);
        SigningStart start = await BeginAsync(credential, cancellationToken).ConfigureAwait(false);

        var additionalReferences = XadesSignatureBuilder.PlanAdditionalReferences(_options.AdditionalDataObjects);
        // The data objects timestamp is a signed property, so the TSA is asked before the bytes to sign exist.
        XadesDataObjectsTimeStamp? dataObjectsTimeStamp = _options.DataObjectsTimestamp is { } dataTsa
            ? await RequestDataObjectsTimeStampAsync(dataTsa, start.HashAlgorithm, _options.OperationId ?? "-", additionalReferences, cancellationToken).ConfigureAwait(false)
            : null;

        ExternalPreparation preparation = PrepareExternal(
            start.Certificate, start.HashAlgorithm, start.SignatureAlgorithmOid, dataObjectsTimeStamp, additionalReferences);
        byte[] preparedXml = AssembleExternal(
            preparation, signatureValue: [], start.Certificate, start.Chain, start.HashAlgorithm, start.SignatureAlgorithmOid,
            dataObjectsTimeStamp, additionalReferences);
        string signatureId = XadesSignatureBuilder.GetLastSignatureId(preparedXml);

        // The policy store is an unsigned property: it goes in now, before the timestamps of phase two.
        if (_options.PolicyStore is { } policyStore)
        {
            preparedXml = XadesSignatureBuilder.EmbedSignaturePolicyStore(preparedXml, policyStore, signatureId);
        }

        var external = (_options.AdditionalDataObjects ?? [])
            .Where(o => o.Uri is not null)
            .Select(o => new XadesDeferredExternalObject { Uri = o.Uri!, Content = o.Content.ToArray() })
            .ToArray();
        var profile = _options.Profile;
        var session = new XadesDeferredSession
        {
            SignedInfo = preparation.SignedInfoCanonical,
            PreparedXml = preparedXml,
            SignatureId = signatureId,
            DetachedContent = _options.Form == XadesForm.Detached ? _xmlData : null,
            ExternalDataObjects = external.Length == 0 ? null : external,
            InputSha256 = Convert.ToHexString(SHA256.HashData(_xmlData)),
            CertificateDer = start.Certificate.RawData,
            ExtraCertificatesDer = start.Chain.Count == 0 ? null : [.. start.Chain.Select(c => c.RawData)],
            HashAlgorithm = start.HashAlgorithm.Name!,
            SignatureAlgorithmOid = start.SignatureAlgorithmOid,
            SigningTime = preparation.SigningTime,
            RequestedLevel = profile.Level,
            LevelFailureBehavior = profile.FailureBehavior,
            TimestampEndpoint = profile.Timestamp?.Endpoint.ToString(),
            ArchiveTimestampEndpoint = profile.ArchiveTimestamp?.Endpoint?.ToString(),
            RevocationPreference = profile.LongTermValidation?.RevocationPreference ?? RevocationPreference.OcspFirst,
            ClockSkewSeconds = DeferredProfile.ClockSkewSecondsToRecord(profile),
            ExtendedForm = _options.ExtendedForm,
            OperationId = _options.OperationId,
        };

        byte[] sessionData = session.Protect(sessionIntegrityKey);
        _options.Dependencies.Logger.DeferredPrepared(
            _options.OperationId ?? "-", signatureId, preparation.SignedInfoCanonical.Length, sessionData.Length);
        return new XadesDeferredPrepareResult
        {
            DataToSign = preparation.SignedInfoCanonical,
            SessionData = sessionData,
            DigestAlgorithm = start.HashAlgorithm.Name!,
            SignatureAlgorithmOid = start.SignatureAlgorithmOid,
            Warnings = start.Warnings.AsReadOnly(),
            RsaPssParameters = start.RsaPssParameters,
            OperationId = _options.OperationId,
        };
    }

    /// <summary>
    /// Phase two: verifies <paramref name="rawSignature"/> against the certificate of the session, writes it
    /// into the prepared document and takes the signature to the requested level. The outcome, signed or
    /// refused, is recorded by the audit sink.
    /// </summary>
    internal async Task<XadesSigningResult> CompleteDeferredAsync(
        XadesDeferredSession session, byte[] rawSignature, CancellationToken cancellationToken)
    {
        using X509Certificate2 certificate = CertificateLoader.LoadCertificate(session.CertificateDer);
        List<X509Certificate2> chain = [.. (session.ExtraCertificatesDer ?? []).Select(CertificateLoader.LoadCertificate)];
        try
        {
            return await SignatureAudit.RunAsync(
                _options.AuditSink,
                () => SignatureAuditEvent.Start("XAdES", _options.OperationId, _options.Profile.Level, certificate, _options.SigningPolicy, default)
                    with
                { InputSha256 = session.InputSha256 },
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

    private async Task<XadesSigningResult> CompleteDeferredCoreAsync(
        XadesDeferredSession session,
        byte[] rawSignature,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        ResolvedSigningAlgorithm algorithm = SigningAlgorithmResolver.Resolve(
            certificate, new HashAlgorithmName(session.HashAlgorithm), hashAlgorithmExplicitlySet: true, session.SignatureAlgorithmOid);
        if (!CmsSignatureBuilder.VerifyExternalSignature(
                session.SignedInfo, rawSignature, certificate, algorithm.HashAlgorithm, algorithm.SignatureAlgorithmOid))
        {
            throw new SigningException(
                "The external signature does not verify with the certificate of the session.",
                SigningErrorReason.ExternalSignerReturnedInvalidSignature);
        }

        _options.Dependencies.Logger.DeferredCompleting(_options.OperationId ?? "-", session.SignatureId, rawSignature.Length);
        byte[] signedXml = XadesSignatureBuilder.SetSignatureValue(
            session.PreparedXml, session.SignatureId, XadesSignatureBuilder.XmlSignatureValue(rawSignature, certificate));
        return await FinishAsync(
            signedXml, session.SignatureId, certificate, chain, algorithm.HashAlgorithm, [], stopwatch, cancellationToken).ConfigureAwait(false);
    }
}
