using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.XAdES;

/// <summary>Immutable fluent builder for XAdES signatures (ETSI EN 319 132).</summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XadesSignerBuilder
{
    private readonly byte[] _xmlData;
    private readonly XadesSigningOptions _options;

    internal XadesSignerBuilder(byte[] xmlData, ILogger? logger = null)
    {
        _xmlData = (byte[])xmlData.Clone();
        _options = new XadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Profile: AdesBaselineProfile.Basic(),
            Form: XadesForm.Enveloped,
            DataUri: null,
            CommitmentType: null,
            SignaturePolicyOid: null,
            SignaturePolicyUri: null,
            SignerRoles: null,
            DataObjectFormat: null,
            OperationId: null,
            Dependencies: new XadesDependencies(null, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    internal XadesSignerBuilder(byte[] xmlData, ITimestampClientFactory tsaFactory, ILogger? logger = null)
    {
        _xmlData = (byte[])xmlData.Clone();
        _options = new XadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Profile: AdesBaselineProfile.Basic(),
            Form: XadesForm.Enveloped,
            DataUri: null,
            CommitmentType: null,
            SignaturePolicyOid: null,
            SignaturePolicyUri: null,
            SignerRoles: null,
            DataObjectFormat: null,
            OperationId: null,
            Dependencies: new XadesDependencies(tsaFactory, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    private XadesSignerBuilder(byte[] xmlData, XadesSigningOptions options)
    {
        _xmlData = xmlData;
        _options = options;
    }

    /// <summary>Sets the signing certificate (must have a private key for local signing).</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>A new builder with the local credential configured.</returns>
    public XadesSignerBuilder WithCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return WithCredential(new XadesLocalCredential(certificate, []));
    }

    /// <summary>Sets the signing certificate and its chain.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty. The collection is defensively copied.
    /// </param>
    /// <returns>A new builder with the local credential configured.</returns>
    public XadesSignerBuilder WithCertificate(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return WithCredential(new XadesLocalCredential(certificate, CopyChain(chain)));
    }

    /// <summary>Configures external signing (HSM, cloud KMS, A3 token).</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation.</param>
    /// <returns>A new builder with the external credential configured.</returns>
    public XadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        IExternalSigner signer)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        return WithCredential(new XadesExternalCredential(certificate, [], signer));
    }

    /// <summary>Configures external signing with a pre-fetched certificate chain.</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation.</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty. The collection is defensively copied.
    /// </param>
    /// <returns>A new builder with the external credential configured.</returns>
    public XadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        IExternalSigner signer,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(chain);
        return WithCredential(new XadesExternalCredential(certificate, CopyChain(chain), signer));
    }

    /// <summary>Sets the hash algorithm (default: SHA-256).</summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>A new builder with the hash algorithm configured.</returns>
    public XadesSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        With(_options with { HashAlgorithm = algorithm, HashAlgorithmExplicitlySet = true });

    /// <summary>Sets an explicit signature algorithm OID (e.g. RSA PKCS#1, RSA-PSS, ECDSA).</summary>
    /// <param name="signatureAlgorithmOid">The signature algorithm OID.</param>
    /// <returns>A new builder with the signature algorithm configured.</returns>
    public XadesSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        return With(_options with { SignatureAlgorithmOid = signatureAlgorithmOid });
    }

    /// <summary>
    /// Replaces the complete baseline profile. The requested ETSI level and all of its
    /// dependencies travel together in one immutable value; no other method changes the level.
    /// </summary>
    /// <param name="profile">The complete baseline profile (B-B, B-T, B-LT, or B-LTA).</param>
    /// <returns>A new builder with the profile configured.</returns>
    public XadesSignerBuilder WithLevel(AdesBaselineProfile profile)
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
    public XadesSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return With(_options with
        {
            Dependencies = _options.Dependencies with { HttpClientProvider = provider }
        });
    }

    /// <summary>Sets an operation ID for log correlation.</summary>
    /// <param name="operationId">The operation ID.</param>
    /// <returns>A new builder with the operation ID configured.</returns>
    public XadesSignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return With(_options with { OperationId = operationId });
    }

    /// <summary>Sets the XAdES signature packaging form (Enveloped, Detached, Enveloping).</summary>
    /// <param name="form">The XAdES packaging form.</param>
    /// <returns>A new builder with the form configured.</returns>
    public XadesSignerBuilder WithForm(XadesForm form) =>
        With(_options with { Form = form });

    /// <summary>Sets the data URI for Detached form signatures.</summary>
    /// <param name="dataUri">The data object URI.</param>
    /// <returns>A new builder with the data URI configured.</returns>
    public XadesSignerBuilder WithDataUri(string dataUri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataUri);
        return With(_options with { DataUri = dataUri });
    }

    /// <summary>Sets the explicit claimed signing time (default: UTC now).</summary>
    /// <param name="signingTime">The claimed signing time.</param>
    /// <returns>A new builder with the signing time configured.</returns>
    public XadesSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        With(_options with { SigningTime = signingTime });

    /// <summary>Sets the commitment type indication (e.g. ProofOfOrigin, ProofOfApproval).</summary>
    /// <param name="commitmentType">The commitment type.</param>
    /// <returns>A new builder with the commitment type configured.</returns>
    public XadesSignerBuilder WithCommitmentType(CommitmentType commitmentType) =>
        With(_options with { CommitmentType = commitmentType });

    /// <summary>Sets the signature policy OID and optional policy document URI.</summary>
    /// <param name="oid">The signature policy OID.</param>
    /// <param name="uri">Optional policy document URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public XadesSignerBuilder WithSignaturePolicy(string oid, string? uri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        return With(_options with { SignaturePolicyOid = oid, SignaturePolicyUri = uri });
    }

    /// <summary>Set claimed signer role(s) (e.g., "Manager", "Approver").</summary>
    /// <param name="roles">The signer roles. The collection is defensively copied.</param>
    /// <returns>A new builder with the signer roles configured.</returns>
    public XadesSignerBuilder WithSignerRoles(IReadOnlyList<string> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        return With(_options with { SignerRoles = roles.ToList().AsReadOnly() });
    }

    /// <summary>Set a single claimed signer role.</summary>
    /// <param name="role">The signer role.</param>
    /// <returns>A new builder with the signer role configured.</returns>
    public XadesSignerBuilder WithSignerRole(string role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        return With(_options with { SignerRoles = [role] });
    }

    /// <summary>Set the data object format (MIME type + object reference URI).</summary>
    /// <param name="format">The data object format.</param>
    /// <returns>A new builder with the data object format configured.</returns>
    public XadesSignerBuilder WithDataObjectFormat(DataObjectFormat format)
    {
        ArgumentNullException.ThrowIfNull(format);
        return With(_options with { DataObjectFormat = format });
    }

    /// <summary>Sets a logger for diagnostic output.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>A new builder with the logger configured.</returns>
    public XadesSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(_options with
        {
            Dependencies = _options.Dependencies with { Logger = logger }
        });
    }

    /// <summary>Signs the XML document and returns the signed bytes.</summary>
    /// <remarks>
    /// Throws <see cref="SigningException"/> when the requested level profile is
    /// configured for best-effort downgrades; use
    /// <see cref="SignWithDetailsAsync(CancellationToken)"/> in that case.
    /// </remarks>
    /// <returns>The signed XML bytes.</returns>
    public async Task<byte[]> SignAsync(CancellationToken cancellationToken = default)
    {
        EnsureStrictProfile();
        var result = await SignWithDetailsAsync(cancellationToken).ConfigureAwait(false);
        return result.SignedArtifact;
    }

    /// <summary>Signs the XML document and returns a detailed result with level facts and warnings.</summary>
    /// <returns>The detailed XAdES signing result.</returns>
    public async Task<XadesSigningResult> SignWithDetailsAsync(
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

        byte[] signedXml;
        if (credential is XadesExternalCredential external)
        {
            signedXml = await SignExternalCoreAsync(external, certificate, chain, sigAlgOid, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            signedXml = SignLocalCore(certificate, chain, sigAlgOid);
        }

        byte[]? timestampTokenBytes = null;
        if (profile.Timestamp is not null)
        {
            try
            {
                timestampTokenBytes = await ApplyTimestampAsync(signedXml, hashAlg, profile.Timestamp, cancellationToken).ConfigureAwait(false);
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
                signedXml = XadesSignatureBuilder.EmbedSignatureTimeStamp(signedXml, timestampTokenBytes);
            }
        }

        bool hasLtvMaterial = false;
        if (timestampTokenBytes is not null && profile.Level >= AdesBaselineLevel.LongTerm)
        {
            byte[]? ltvXml = await ApplyLtvAsync(signedXml, certificate, chain, cancellationToken).ConfigureAwait(false);
            if (ltvXml is not null)
            {
                signedXml = ltvXml;
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
                signedXml = await ApplyArchiveTimestampAsync(signedXml, hashAlg, profile, cancellationToken).ConfigureAwait(false);
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

        return new XadesSigningResult
        {
            SignedArtifact = signedXml,
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

    private static void ValidatePrerequisites(XadesSigningCredential credential)
    {
        var certificate = GetCertificate(credential);
        if (credential is not XadesExternalCredential && !certificate.HasPrivateKey)
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

    private static X509Certificate2 GetCertificate(XadesSigningCredential credential) => credential switch
    {
        XadesLocalCredential c => c.Certificate,
        XadesExternalCredential c => c.Certificate,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    private static IReadOnlyList<X509Certificate2> GetChain(XadesSigningCredential credential) => credential switch
    {
        XadesLocalCredential c => c.Chain,
        XadesExternalCredential c => c.Chain,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    private byte[] SignLocalCore(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        string sigAlgOid)
    {
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;
        return XadesSignatureBuilder.BuildSignature(
            _xmlData, certificate, _options.HashAlgorithm, signingTime, chain,
            _options.CommitmentType, _options.SignaturePolicyOid, _options.SignaturePolicyUri,
            sigAlgOid, _options.Form, _options.SignerRoles, _options.DataObjectFormat,
            _options.Dependencies.Logger, _options.DataUri);
    }

    private async Task<byte[]> SignExternalCoreAsync(
        XadesExternalCredential external,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        string sigAlgOid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var hashAlg = _options.HashAlgorithm;
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;

        byte[] signedInfoBytes = XadesSignatureBuilder.BuildSignedInfoToHash(
            _xmlData, certificate, hashAlg, signingTime, _options.Form,
            _options.CommitmentType, _options.SignaturePolicyOid, _options.SignaturePolicyUri,
            sigAlgOid, _options.SignerRoles, _options.DataObjectFormat,
            out string signedPropertiesId,
            out byte[] signedInfoXml,
            out string? dataObjectId, _options.DataUri);

        var request = new ExternalSigningRequest(
            signedInfoBytes,
            hashAlg,
            sigAlgOid,
            ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo,
            _options.OperationId);
        ReadOnlyMemory<byte> signature = await external.Signer.SignAsync(request, cancellationToken).ConfigureAwait(false);
        if (signature.Length == 0)
        {
            throw new SigningException(
                "External signer returned an empty signature.",
                SigningErrorReason.ExternalSignerReturnedEmpty);
        }

        return XadesSignatureBuilder.CompleteWithExternalSignature(
            _xmlData, certificate, hashAlg, signingTime, chain,
            _options.CommitmentType, _options.SignaturePolicyOid, _options.SignaturePolicyUri,
            sigAlgOid, signedInfoXml, signature.ToArray(), signedPropertiesId,
            _options.SignerRoles, _options.DataObjectFormat, _options.Form, _options.DataUri, dataObjectId);
    }

    private async Task<byte[]?> ApplyTimestampAsync(
        byte[] signedXml,
        HashAlgorithmName hashAlg,
        TimestampOptions timestampOptions,
        CancellationToken cancellationToken)
    {
        var tsaClient = CreateTimestampClient(timestampOptions.Endpoint.ToString(), timestampOptions.HttpClientProvider);
        var sigValue = XadesSignatureBuilder.ExtractSignatureValue(signedXml);
        byte[] tsToken = await tsaClient.GetTimestampAsync(sigValue, hashAlg, cancellationToken).ConfigureAwait(false);

        return XadesSignatureBuilder.EmbedSignatureTimeStamp(signedXml, tsToken);
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
        byte[] signedXml,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        CancellationToken cancellationToken)
    {
        var profile = _options.Profile;
        var logger = _options.Dependencies.Logger;
        var ltvProvider = profile.LongTermValidation!.HttpClientProvider ?? _options.Dependencies.HttpClientProvider;

        var chainCerts = new List<X509Certificate2> { certificate };
        foreach (var c in chain)
        {
            if (!chainCerts.Any(x => x.Thumbprint == c.Thumbprint))
            {
                chainCerts.Add(c);
            }
        }

        var ltvData = await LtvDataCollector.CollectAsync(
            ltvProvider.GetClient(), certificate, chainCerts, logger, cancellationToken: cancellationToken).ConfigureAwait(false);

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

        return XadesSignatureBuilder.EmbedLtvData(signedXml, ltvData);
    }

    private async Task<byte[]> ApplyArchiveTimestampAsync(
        byte[] signedXml,
        HashAlgorithmName hashAlg,
        AdesBaselineProfile profile,
        CancellationToken cancellationToken)
    {
        var archiveOptions = profile.ArchiveTimestamp;
        var timestampOptions = profile.Timestamp!;
        var endpoint = archiveOptions?.Endpoint ?? timestampOptions.Endpoint;
        var scopedProvider = archiveOptions?.HttpClientProvider ?? timestampOptions.HttpClientProvider;

        var tsaClient = CreateTimestampClient(endpoint.ToString(), scopedProvider);
        byte[] xmlHash = CryptoUtility.ComputeHash(signedXml, hashAlg);
        byte[] tsToken = await tsaClient.GetTimestampAsync(xmlHash, hashAlg, cancellationToken).ConfigureAwait(false);

        return XadesSignatureBuilder.EmbedArchiveTimeStamp(signedXml, tsToken);
    }

    private XadesSignerBuilder WithCredential(XadesSigningCredential credential) =>
        With(_options with { Credential = credential });

    private XadesSignerBuilder With(XadesSigningOptions options) =>
        new(_xmlData, options);

    private static IReadOnlyList<X509Certificate2> CopyChain(IReadOnlyList<X509Certificate2> chain) =>
        chain.ToList().AsReadOnly();
}
