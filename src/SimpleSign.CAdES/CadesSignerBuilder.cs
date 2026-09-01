using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.CAdES;

/// <summary>
/// Immutable fluent builder for CAdES signatures (ETSI EN 319 122).
/// Created via <c>CadesSigner.Document(data)</c> and configured with
/// <c>With*</c> methods that return a new builder instance.
/// </summary>
public sealed class CadesSignerBuilder
{
    private readonly byte[] _data;
    private readonly CadesSigningOptions _options;

    internal CadesSignerBuilder(byte[] data, ILogger? logger = null)
    {
        _data = (byte[])data.Clone();
        _options = new CadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Profile: AdesBaselineProfile.Basic(),
            OperationId: null,
            CommitmentType: null,
            SignaturePolicyOid: null,
            SignaturePolicyUri: null,
            ContentType: CadesContentType.Detached,
            Dependencies: new CadesDependencies(null, null, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    internal CadesSignerBuilder(byte[] data, ITimestampClientFactory tsaFactory, ILogger? logger = null)
    {
        _data = (byte[])data.Clone();
        _options = new CadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Profile: AdesBaselineProfile.Basic(),
            OperationId: null,
            CommitmentType: null,
            SignaturePolicyOid: null,
            SignaturePolicyUri: null,
            ContentType: CadesContentType.Detached,
            Dependencies: new CadesDependencies(tsaFactory, null, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    internal CadesSignerBuilder(byte[] data, ITimestampClientFactory tsaFactory, ICmsParser cmsParser, ILogger? logger = null)
    {
        _data = (byte[])data.Clone();
        _options = new CadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Profile: AdesBaselineProfile.Basic(),
            OperationId: null,
            CommitmentType: null,
            SignaturePolicyOid: null,
            SignaturePolicyUri: null,
            ContentType: CadesContentType.Detached,
            Dependencies: new CadesDependencies(tsaFactory, cmsParser, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    private CadesSignerBuilder(byte[] data, CadesSigningOptions options)
    {
        _data = data;
        _options = options;
    }

    /// <summary>Sets the signer's certificate (must have a private key for local signing).</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>A new builder with the local credential configured.</returns>
    public CadesSignerBuilder WithCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return WithCredential(new CadesLocalCredential(certificate, []));
    }

    /// <summary>Sets the signer's certificate and its chain.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty. The collection is defensively copied.
    /// </param>
    /// <returns>A new builder with the local credential configured.</returns>
    public CadesSignerBuilder WithCertificate(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return WithCredential(new CadesLocalCredential(certificate, CopyChain(chain)));
    }

    /// <summary>Uses an external signer (HSM, cloud KMS, A3 token).</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation.</param>
    /// <returns>A new builder with the external credential configured.</returns>
    public CadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        IExternalSigner signer)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        return WithCredential(new CadesExternalCredential(certificate, [], signer));
    }

    /// <summary>Uses an external signer with a pre-fetched certificate chain.</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation.</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty. The collection is defensively copied.
    /// </param>
    /// <returns>A new builder with the external credential configured.</returns>
    public CadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        IExternalSigner signer,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(chain);
        return WithCredential(new CadesExternalCredential(certificate, CopyChain(chain), signer));
    }

    /// <summary>Explicitly sets the hash algorithm. Default: SHA-256.</summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>A new builder with the hash algorithm configured.</returns>
    public CadesSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        With(_options with { HashAlgorithm = algorithm, HashAlgorithmExplicitlySet = true });

    /// <summary>Explicitly sets the signature algorithm OID.</summary>
    /// <param name="signatureAlgorithmOid">The signature algorithm OID.</param>
    /// <returns>A new builder with the signature algorithm configured.</returns>
    public CadesSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        return With(_options with { SignatureAlgorithmOid = signatureAlgorithmOid });
    }

    /// <summary>Sets an explicit claimed signing time. Default: UTC now.</summary>
    /// <param name="signingTime">The claimed signing time.</param>
    /// <returns>A new builder with the signing time configured.</returns>
    public CadesSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        With(_options with { SigningTime = signingTime });

    /// <summary>
    /// Replaces the complete baseline profile. The requested ETSI level and all of its
    /// dependencies travel together in one immutable value; no other method changes the level.
    /// </summary>
    /// <param name="profile">The complete baseline profile (B-B, B-T, B-LT, or B-LTA).</param>
    /// <returns>A new builder with the profile configured.</returns>
    public CadesSignerBuilder WithLevel(AdesBaselineProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return With(_options with { Profile = profile });
    }

    /// <summary>
    /// Sets a builder-wide <see cref="IHttpClientProvider"/> used as the fallback for all
    /// network operations that do not carry their own scoped provider (timestamp,
    /// long-term validation material, archive timestamp).
    /// </summary>
    /// <param name="provider">The HTTP client provider.</param>
    /// <returns>A new builder with the provider configured.</returns>
    public CadesSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return With(_options with
        {
            Dependencies = _options.Dependencies with { HttpClientProvider = provider }
        });
    }

    /// <summary>Sets the content type. Detached = .p7s (default), Enveloped = .p7m with embedded data.</summary>
    /// <param name="contentType">The CAdES content type.</param>
    /// <returns>A new builder with the content type configured.</returns>
    public CadesSignerBuilder WithContentType(CadesContentType contentType) =>
        With(_options with { ContentType = contentType });

    /// <summary>
    /// Sets an operation ID for log correlation (appears in all log messages
    /// produced by this signing operation).
    /// </summary>
    /// <param name="operationId">The operation ID.</param>
    /// <returns>A new builder with the operation ID configured.</returns>
    public CadesSignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return With(_options with { OperationId = operationId });
    }

    /// <summary>Sets the commitment type indication (e.g. ProofOfOrigin, ProofOfApproval).</summary>
    /// <param name="commitmentType">The commitment type.</param>
    /// <returns>A new builder with the commitment type configured.</returns>
    public CadesSignerBuilder WithCommitmentType(CommitmentType commitmentType) =>
        With(_options with { CommitmentType = commitmentType });

    /// <summary>Sets the signature policy identifier and optional URI.</summary>
    /// <param name="oid">The signature policy OID.</param>
    /// <param name="uri">Optional policy document URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public CadesSignerBuilder WithSignaturePolicy(string oid, string? uri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        return With(_options with { SignaturePolicyOid = oid, SignaturePolicyUri = uri });
    }

    /// <summary>Sets the logger for diagnostic output.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>A new builder with the logger configured.</returns>
    public CadesSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(_options with
        {
            Dependencies = _options.Dependencies with { Logger = logger }
        });
    }

    /// <summary>Signs the data and returns the DER-encoded CMS/PKCS#7 SignedData.</summary>
    /// <remarks>
    /// Throws <see cref="SigningException"/> when the requested level profile is
    /// configured for best-effort downgrades; use
    /// <see cref="SignWithDetailsAsync(CancellationToken)"/> in that case.
    /// </remarks>
    /// <returns>The DER-encoded CMS signature bytes.</returns>
    public async Task<byte[]> SignAsync(CancellationToken cancellationToken = default)
    {
        EnsureStrictProfile();
        var result = await SignWithDetailsAsync(cancellationToken).ConfigureAwait(false);
        return result.SignedArtifact;
    }

    /// <summary>
    /// Signs the data and returns a structured result with the CMS bytes, requested and
    /// achieved baseline levels, actual feature flags, and warnings.
    /// </summary>
    /// <returns>The detailed CAdES signing result.</returns>
    public async Task<CadesSigningResult> SignWithDetailsAsync(
        CancellationToken cancellationToken = default)
    {
        var credential = _options.Credential
            ?? throw new SigningException(
                "Certificate not set. Call WithCertificate() or WithExternalSigner() before signing.",
                SigningErrorReason.CredentialMissing);
        var certificate = GetCertificate(credential);
        var chain = GetChain(credential);
        var profile = _options.Profile;

        ValidatePrerequisites(credential);

        var warnings = new List<SigningWarning>();
        var hashAlg = _options.HashAlgorithm;
        string sigAlgOid = _options.SignatureAlgorithmOid
            ?? CryptoUtility.DetectSignatureAlgorithmOid(certificate, hashAlg);
        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(certificate, sigAlgOid);

        byte[] cms;
        if (credential is CadesExternalCredential external)
        {
            cms = await SignExternalCoreAsync(external, certificate, chain, sigAlgOid, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            cms = SignLocalCore(certificate, chain, sigAlgOid);
        }

        byte[]? timestampTokenBytes = null;
        if (profile.Timestamp is not null)
        {
            try
            {
                timestampTokenBytes = await ApplyTimestampAsync(cms, hashAlg, profile.Timestamp, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
                {
                    throw new SigningException(
                        $"Signature timestamp request failed: {ex.Message}",
                        SigningErrorReason.NetworkFailure,
                        ex);
                }

                AddDowngradeWarnings(warnings, SigningWarningCode.SignatureTimestampUnavailable,
                    $"Signature timestamp could not be applied: {ex.Message}");
            }

            if (timestampTokenBytes is not null)
            {
                cms = TimestampClient.EmbedTimestampInCms(cms, timestampTokenBytes);
            }
        }

        bool hasLtvMaterial = false;
        if (timestampTokenBytes is not null && profile.Level >= AdesBaselineLevel.LongTerm)
        {
            byte[]? ltvCms = await ApplyLtvAsync(cms, certificate, chain, cancellationToken).ConfigureAwait(false);
            if (ltvCms is not null)
            {
                cms = ltvCms;
                hasLtvMaterial = true;
            }
            else
            {
                AddDowngradeWarnings(warnings, SigningWarningCode.LongTermValidationMaterialUnavailable,
                    "LTV was requested but no certificate and revocation data could be collected.");
            }
        }

        bool hasArchiveTimestamp = false;
        if (hasLtvMaterial && profile.Level >= AdesBaselineLevel.Archive)
        {
            try
            {
                cms = await ApplyArchiveTimestampAsync(cms, hashAlg, profile, cancellationToken).ConfigureAwait(false);
                hasArchiveTimestamp = true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
                {
                    throw new SigningException(
                        $"Archive timestamp request failed: {ex.Message}",
                        SigningErrorReason.NetworkFailure,
                        ex);
                }

                AddDowngradeWarnings(warnings, SigningWarningCode.ArchiveTimestampUnavailable,
                    $"Archive timestamp could not be applied: {ex.Message}");
            }
        }

        var achieved = ComputeAchievedLevel(timestampTokenBytes, hasLtvMaterial, hasArchiveTimestamp);

        return new CadesSigningResult
        {
            SignedArtifact = cms,
            RequestedLevel = profile.Level,
            AchievedLevel = achieved,
            HasSignatureTimestamp = timestampTokenBytes is not null,
            HasLongTermValidationMaterial = hasLtvMaterial,
            HasArchiveTimestamp = hasArchiveTimestamp,
            Warnings = warnings.AsReadOnly()
        };
    }

    private static AdesBaselineLevel ComputeAchievedLevel(
        byte[]? timestampTokenBytes,
        bool hasLtvMaterial,
        bool hasArchiveTimestamp)
    {
        if (timestampTokenBytes is null)
        {
            return AdesBaselineLevel.Basic;
        }

        if (!hasLtvMaterial)
        {
            return AdesBaselineLevel.Timestamped;
        }

        return hasArchiveTimestamp ? AdesBaselineLevel.Archive : AdesBaselineLevel.LongTerm;
    }

    private static void AddDowngradeWarnings(List<SigningWarning> warnings, SigningWarningCode code, string message)
    {
        warnings.Add(new SigningWarning(code, message));
        warnings.Add(new SigningWarning(
            SigningWarningCode.LevelDowngraded,
            "The requested baseline level could not be achieved; the artifact was downgraded."));
    }

    private void EnsureStrictProfile()
    {
        if (_options.Profile.FailureBehavior == SigningLevelFailureBehavior.ReturnLowerLevel)
        {
            throw new SigningException(
                "The configured baseline profile allows best-effort level downgrades. " +
                "Use SignWithDetailsAsync() so the achieved level and warnings are reported.",
                SigningErrorReason.DowngradeRequiresDetailedResult);
        }
    }

    private static void ValidatePrerequisites(CadesSigningCredential credential)
    {
        var certificate = GetCertificate(credential);
        if (credential is not CadesExternalCredential && !certificate.HasPrivateKey)
        {
            throw new SigningException(
                "Certificate must have a private key for local signing. Use WithExternalSigner() instead.",
                SigningErrorReason.PrivateKeyMissing);
        }

        if (certificate.NotAfter < DateTime.UtcNow)
        {
            throw new CertificateValidationException(
                $"Certificate '{certificate.Subject}' expired on {certificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC. Cannot sign with an expired certificate.",
                certificate.Thumbprint,
                certificate.Subject);
        }
    }

    private static X509Certificate2 GetCertificate(CadesSigningCredential credential) => credential switch
    {
        CadesLocalCredential c => c.Certificate,
        CadesExternalCredential c => c.Certificate,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    private static IReadOnlyList<X509Certificate2> GetChain(CadesSigningCredential credential) => credential switch
    {
        CadesLocalCredential c => c.Chain,
        CadesExternalCredential c => c.Chain,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    private byte[] SignLocalCore(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        string sigAlgOid)
    {
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;
        var extraAttributes = BuildSignedAttributesInternal();
        byte[]? eContent = _options.ContentType == CadesContentType.Enveloped ? _data : null;

        return CmsSignatureBuilder.Build(
            _data, certificate, _options.HashAlgorithm, signingTime,
            chain, extraAttributes,
            padesAttributes: false,
            signatureAlgorithmOid: sigAlgOid,
            logger: _options.Dependencies.Logger,
            eContent: eContent);
    }

    private async Task<byte[]> SignExternalCoreAsync(
        CadesExternalCredential external,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        string sigAlgOid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var hashAlg = _options.HashAlgorithm;
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;
        string digestOid = CmsSignatureBuilder.GetDigestOid(hashAlg);

        byte[] contentHash = CmsSignatureBuilder.ComputeHash(_data, hashAlg);
        var extraAttributes = BuildSignedAttributesInternal();

        byte[] signedAttrs = CmsSignatureBuilder.BuildSignedAttributes(
            contentHash, digestOid, signingTime, certificate, extraAttributes,
            padesAttributes: false);

        var request = new ExternalSigningRequest(
            signedAttrs,
            hashAlg,
            sigAlgOid,
            ExternalSigningPayloadKind.CmsSignedAttributes,
            _options.OperationId);
        ReadOnlyMemory<byte> signature = await external.Signer.SignAsync(request, cancellationToken).ConfigureAwait(false);
        if (signature.Length == 0)
        {
            throw new SigningException(
                "External signer returned an empty signature.",
                SigningErrorReason.ExternalSignerReturnedEmpty);
        }

        List<X509Certificate2> allCerts = [certificate, .. chain];
        byte[]? eContent = _options.ContentType == CadesContentType.Enveloped ? _data : null;

        return CmsSignatureBuilder.BuildSignedData(
            digestOid, sigAlgOid, hashAlg, signedAttrs,
            signature.ToArray(), certificate, allCerts,
            eContent: eContent);
    }

    private IReadOnlyList<CmsAttribute>? BuildSignedAttributesInternal()
    {
        var attrs = new List<CmsAttribute>();

        if (_options.CommitmentType.HasValue)
        {
            attrs.Add(CmsAttribute.CommitmentTypeIndication(_options.CommitmentType.Value));
        }

        if (_options.SignaturePolicyOid is not null)
        {
            attrs.Add(CmsAttribute.SignaturePolicyIdentifier(
                _options.SignaturePolicyOid, _options.SignaturePolicyUri));
        }

        return attrs.Count > 0 ? attrs : null;
    }

    private async Task<byte[]?> ApplyTimestampAsync(
        byte[] cms,
        HashAlgorithmName hashAlg,
        TimestampOptions timestampOptions,
        CancellationToken cancellationToken)
    {
        var tsaClient = CreateTimestampClient(timestampOptions.Endpoint.ToString(), timestampOptions.HttpClientProvider);
        byte[] tsToken = await tsaClient.GetTimestampAsync(
            TimestampClient.ExtractSignatureValue(cms), hashAlg, cancellationToken).ConfigureAwait(false);
        return TimestampClient.EmbedTimestampInCms(cms, tsToken);
    }

    private ITimestampClient CreateTimestampClient(string endpoint, IHttpClientProvider? scopedProvider)
    {
        if (_options.Dependencies.TsaFactory is not null)
        {
            return _options.Dependencies.TsaFactory.Create(endpoint);
        }

        var provider = scopedProvider ?? _options.Dependencies.HttpClientProvider;
        return new TimestampClient(provider.GetClient(), endpoint, _options.Dependencies.Logger);
    }

    private async Task<byte[]?> ApplyLtvAsync(
        byte[] cms,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        CancellationToken cancellationToken)
    {
        var profile = _options.Profile;
        var logger = _options.Dependencies.Logger;
        var cmsData = _options.Dependencies.CmsParser is not null
            ? _options.Dependencies.CmsParser.Parse(cms, logger)
            : CmsParser.Parse(cms, logger);
        byte[]? timestampToken = cmsData?.SignatureTimestampToken;

        var allKnownCerts = new List<X509Certificate2> { certificate };
        foreach (var cert in chain)
        {
            if (!allKnownCerts.Any(c => c.Thumbprint == cert.Thumbprint))
            {
                allKnownCerts.Add(cert);
            }
        }

        if (timestampToken is not null)
        {
            var tsaCerts = TsaCertificateExtractor.ExtractCertificates(timestampToken);
            foreach (var cert in tsaCerts)
            {
                if (!allKnownCerts.Any(c => c.Thumbprint == cert.Thumbprint))
                {
                    allKnownCerts.Add(cert);
                }
            }
        }

        var ltvProvider = profile.LongTermValidation!.HttpClientProvider ?? _options.Dependencies.HttpClientProvider;
        var ltvData = await LtvDataCollector.CollectAsync(
            ltvProvider.GetClient(), certificate, allKnownCerts, logger, cancellationToken: cancellationToken).ConfigureAwait(false);

        bool hasLtvMaterial = ltvData.CertificateRawData.Count > 0
            && (ltvData.OcspResponses.Count > 0 || ltvData.Crls.Count > 0);
        if (!hasLtvMaterial)
        {
            if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
            {
                throw new SigningException(
                    "LTV was requested but no certificate and revocation data could be collected. " +
                    "The requested B-LT/B-LTA level cannot be produced.",
                    SigningErrorReason.LevelNotAchievable);
            }

            return null;
        }

        var unsignedAttrs = new List<CmsAttribute>();
        if (ltvData.CertificateRawData.Count > 0)
        {
            unsignedAttrs.Add(CmsAttribute.CertValues([.. ltvData.CertificateRawData]));
        }

        if (ltvData.OcspResponses.Count > 0 || ltvData.Crls.Count > 0)
        {
            unsignedAttrs.Add(CmsAttribute.RevocationValues(
                ltvData.OcspResponses.Count > 0 ? [.. ltvData.OcspResponses] : null,
                ltvData.Crls.Count > 0 ? [.. ltvData.Crls] : null));
        }

        return unsignedAttrs.Count > 0
            ? CmsSignatureBuilder.AddUnsignedAttributes(cms, unsignedAttrs)
            : cms;
    }

    private async Task<byte[]> ApplyArchiveTimestampAsync(
        byte[] cms,
        HashAlgorithmName hashAlg,
        AdesBaselineProfile profile,
        CancellationToken cancellationToken)
    {
        var archiveOptions = profile.ArchiveTimestamp;
        var timestampOptions = profile.Timestamp!;
        var endpoint = archiveOptions?.Endpoint ?? timestampOptions.Endpoint;
        var scopedProvider = archiveOptions?.HttpClientProvider ?? timestampOptions.HttpClientProvider;

        var tsaClient = CreateTimestampClient(endpoint.ToString(), scopedProvider);
        byte[] cmsHash = CryptoUtility.ComputeHash(cms, hashAlg);
        byte[] tsToken = await tsaClient.GetTimestampAsync(cmsHash, hashAlg, cancellationToken).ConfigureAwait(false);

        return CmsSignatureBuilder.AddUnsignedAttributes(cms,
        [
            CmsAttribute.Create(Oids.ArchiveTimeStamp, tsToken)
        ]);
    }

    private CadesSignerBuilder WithCredential(CadesSigningCredential credential) =>
        With(_options with { Credential = credential });

    private CadesSignerBuilder With(CadesSigningOptions options) =>
        new(_data, options);

    private static IReadOnlyList<X509Certificate2> CopyChain(IReadOnlyList<X509Certificate2> chain) =>
        chain.ToList().AsReadOnly();
}
