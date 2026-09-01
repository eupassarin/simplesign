using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Enums;
using SimpleSign.Pdf.Exceptions;

namespace SimpleSign.PAdES;

/// <summary>
/// Immutable builder that accumulates PAdES signing configuration.
/// Each method returns a new instance — no shared mutable state.
/// </summary>
public sealed class PadesSignerBuilder
{
    private readonly Stream _inputPdf;
    private readonly PadesSigningOptions _options;

    internal PadesSignerBuilder(Stream inputPdf, ILogger? logger = null)
    {
        _inputPdf = inputPdf;
        _options = new PadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Field: new SignatureFieldOptions(),
            Metadata: null,
            PadesAttributes: true,
            EnforcePdfA: false,
            OperationId: null,
            Profile: AdesBaselineProfile.Basic(),
            CountryExtensions: [],
            Dependencies: new PadesDependencies(null, null, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    internal PadesSignerBuilder(
        Stream inputPdf,
        ITimestampClientFactory tsaFactory,
        ILtvEmbedder ltvEmbedder,
        ILogger? logger = null)
    {
        _inputPdf = inputPdf;
        _options = new PadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Field: new SignatureFieldOptions(),
            Metadata: null,
            PadesAttributes: true,
            EnforcePdfA: false,
            OperationId: null,
            Profile: AdesBaselineProfile.Basic(),
            CountryExtensions: [],
            Dependencies: new PadesDependencies(tsaFactory, ltvEmbedder, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    private PadesSignerBuilder(Stream inputPdf, PadesSigningOptions options)
    {
        _inputPdf = inputPdf;
        _options = options;
    }

    #region Common fluent configuration

    /// <summary>Sets the certificate with private key for local signing.</summary>
    /// <param name="certificate">The signing certificate. Must not be null.</param>
    /// <returns>A new builder with the local credential configured.</returns>
    public PadesSignerBuilder WithCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return WithCredential(new LocalCredential(certificate, []));
    }

    /// <summary>Sets the certificate and its chain for local signing.</summary>
    /// <param name="certificate">The signing certificate. Must not be null.</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty. The collection is defensively copied.
    /// </param>
    /// <returns>A new builder with the local credential configured.</returns>
    public PadesSignerBuilder WithCertificate(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return WithCredential(new LocalCredential(certificate, CopyChain(chain)));
    }

    /// <summary>Configures external signing with an explicit signer contract.</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation (HSM, cloud KMS, A3 token).</param>
    /// <returns>A new builder with the external credential configured.</returns>
    public PadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        IExternalSigner signer)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        return WithCredential(new ExternalCredential(certificate, [], signer));
    }

    /// <summary>Configures external signing with an explicit signer contract and a pre-fetched chain.</summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="signer">The external signer implementation (HSM, cloud KMS, A3 token).</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty. The collection is defensively copied.
    /// </param>
    /// <returns>A new builder with the external credential configured.</returns>
    public PadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        IExternalSigner signer,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(chain);
        return WithCredential(new ExternalCredential(certificate, CopyChain(chain), signer));
    }

    /// <summary>Sets the hash algorithm. Default: SHA-256 (recommended by ICP-Brasil).</summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>A new builder with the hash algorithm configured.</returns>
    public PadesSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        With(_options with { HashAlgorithm = algorithm, HashAlgorithmExplicitlySet = true });

    /// <summary>
    /// Forces a specific signature algorithm, overriding the algorithm inferred from the
    /// certificate's public key type. The primary use case is producing RSASSA-PSS signatures
    /// with a certificate whose public key OID is <c>rsaEncryption</c>
    /// (<c>1.2.840.113549.1.1.1</c>) rather than <c>id-RSASSA-PSS</c> (<c>1.2.840.113549.1.1.10</c>).
    /// Compatibility with the certificate's key type is validated at signing time.
    /// </summary>
    /// <param name="signatureAlgorithmOid">OID of the signature algorithm (e.g., <c>Oids.RsaPss</c>).</param>
    /// <returns>A new builder with the signature algorithm configured.</returns>
    public PadesSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        return With(_options with { SignatureAlgorithmOid = signatureAlgorithmOid });
    }

    /// <summary>
    /// Configures the claimed signing time embedded in the signature.
    /// This is not trusted proof of time; B-T or higher still requires a
    /// signature timestamp via <see cref="WithLevel"/>.
    /// </summary>
    /// <param name="signingTime">The claimed signing time. Default: UTC now.</param>
    /// <returns>A new builder with the signing time configured.</returns>
    public PadesSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        With(_options with { SigningTime = signingTime });

    /// <summary>
    /// Replaces the complete baseline profile. The requested ETSI level and all of its
    /// dependencies travel together in one immutable value; no other method changes the level.
    /// </summary>
    /// <param name="profile">The complete baseline profile (B-B, B-T, B-LT, or B-LTA).</param>
    /// <returns>A new builder with the profile configured.</returns>
    public PadesSignerBuilder WithLevel(AdesBaselineProfile profile)
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
    public PadesSignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return With(_options with
        {
            Dependencies = _options.Dependencies with { HttpClientProvider = provider }
        });
    }

    /// <summary>Sets an operation ID for correlation in log messages.</summary>
    /// <param name="operationId">The operation ID.</param>
    /// <returns>A new builder with the operation ID configured.</returns>
    public PadesSignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return With(_options with { OperationId = operationId });
    }

    /// <summary>Sets the logger for diagnostic output.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>A new builder with the logger configured.</returns>
    public PadesSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(_options with
        {
            Dependencies = _options.Dependencies with { Logger = logger }
        });
    }

    #endregion

    #region PAdES-specific fluent configuration

    /// <summary>Sets the signature field name.</summary>
    /// <param name="fieldName">The PDF signature field name.</param>
    /// <returns>A new builder with the field name configured.</returns>
    public PadesSignerBuilder WithFieldName(string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        return With(_options with { Field = CloneField(fieldName: fieldName) });
    }

    /// <summary>
    /// Configures generic signer metadata for the signature.
    /// Use this for country-agnostic signing with structured metadata.
    /// For Brazil-specific signing, use <c>WithAdvancedSignature</c> from SimpleSign.Brasil.
    /// </summary>
    /// <param name="metadata">The signer metadata.</param>
    /// <returns>A new builder with the metadata configured.</returns>
    public PadesSignerBuilder WithMetadata(SignatureMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        string reason = metadata.Reason ?? string.Empty;
        string location = metadata.Location ?? metadata.InstitutionName ?? string.Empty;

        string contactInfo;
        if (metadata.ContactInfo is not null)
        {
            contactInfo = metadata.ContactInfo;
        }
        else
        {
            var contactParts = new List<string>();
            if (metadata.SignerId is not null)
            {
                string label = metadata.SignerIdType ?? "ID";
                contactParts.Add($"{label}: {metadata.SignerId}");
            }
            if (metadata.Email is not null)
            {
                contactParts.Add($"Email: {metadata.Email}");
            }
            if (metadata.IpAddress is not null)
            {
                contactParts.Add($"IP: {metadata.IpAddress}");
            }
            if (metadata.AuthenticationMethod is not null)
            {
                contactParts.Add($"Auth: {metadata.AuthenticationMethod}");
            }
            if (metadata.InstitutionName is not null)
            {
                contactParts.Add($"Org: {metadata.InstitutionName}");
            }
            contactInfo = string.Join(" | ", contactParts);
        }

        var updatedField = CloneField(
            signerName: metadata.SignerName,
            reason: reason,
            location: location,
            contactInfo: contactInfo);

        return With(_options with { Field = updatedField, Metadata = metadata });
    }

    /// <summary>Sets visible metadata on the signature.</summary>
    /// <param name="signerName">Signer display name.</param>
    /// <param name="reason">Signing reason.</param>
    /// <param name="location">Signing location.</param>
    /// <param name="contactInfo">Contact information.</param>
    /// <returns>A new builder with the metadata configured.</returns>
    public PadesSignerBuilder WithMetadata(
        string? signerName = null,
        string? reason = null,
        string? location = null,
        string? contactInfo = null) =>
        With(_options with
        {
            Field = CloneField(signerName: signerName, reason: reason, location: location, contactInfo: contactInfo)
        });

    /// <summary>
    /// Adds a visual appearance (stamp) to the signature on a specific page.
    /// The stamp displays the signer name, date/time, and other configured metadata.
    /// </summary>
    /// <param name="appearance">The visual appearance configuration.</param>
    /// <returns>A new builder with the appearance configured.</returns>
    public PadesSignerBuilder WithAppearance(SignatureAppearance appearance)
    {
        ArgumentNullException.ThrowIfNull(appearance);
        return With(_options with { Field = CloneField(appearance: appearance) });
    }

    /// <summary>
    /// Creates a certification (DocMDP) signature that restricts subsequent document modifications.
    /// Only the first signature in a document can be a certification signature.
    /// </summary>
    /// <param name="level">The permitted modification level after certification.</param>
    /// <returns>A new builder with the certification level configured.</returns>
    public PadesSignerBuilder AsCertification(CertificationLevel level = CertificationLevel.FormFilling) =>
        With(_options with { Field = CloneField(certificationLevel: level) });

    /// <summary>
    /// Signs an existing empty signature field instead of creating a new one.
    /// The field must already exist in the PDF with an empty /V value.
    /// </summary>
    /// <param name="fieldName">The name of the existing signature field (the /T value).</param>
    /// <returns>A new builder with the existing field configured.</returns>
    public PadesSignerBuilder WithExistingField(string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        return With(_options with { Field = CloneField(existingFieldName: fieldName) });
    }

    /// <summary>
    /// Enables PDF/A conformance checking before signing. If the input document is
    /// a PDF/A file and the signature options are incompatible with that level,
    /// a <see cref="SigningException"/> is thrown during signing.
    /// </summary>
    /// <returns>A new builder with PDF/A preservation enabled.</returns>
    public PadesSignerBuilder WithPdfAPreservation() =>
        With(_options with { EnforcePdfA = true });

    /// <summary>
    /// Produces a plain PKCS#7/CMS signature (<c>adbe.pkcs7.detached</c>) without PAdES-specific
    /// attributes (no <c>id-aa-signingCertificateV2</c> / ESS CertV2).
    /// Use this to interoperate with legacy systems or to replicate signatures produced by tools
    /// that predate PAdES (Level: <c>CMS — no PAdES attributes</c>).
    /// </summary>
    /// <remarks>
    /// When this mode is active, the resulting signature is NOT considered PAdES-compliant.
    /// Validators that enforce PAdES (e.g., ITI) may report the signature as non-conformant.
    /// </remarks>
    /// <returns>A new builder configured for legacy CMS output.</returns>
    public PadesSignerBuilder WithLegacyCms()
    {
        var legacyField = new SignatureFieldOptions
        {
            FieldName = _options.Field.FieldName,
            SignerName = _options.Field.SignerName,
            Reason = _options.Field.Reason,
            Location = _options.Field.Location,
            ContactInfo = _options.Field.ContactInfo,
            ContentsReservedBytes = _options.Field.ContentsReservedBytes,
            SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached,
            Appearance = _options.Field.Appearance,
            CertificationLevel = _options.Field.CertificationLevel,
            ExistingFieldName = _options.Field.ExistingFieldName
        };
        return With(_options with { Field = legacyField, PadesAttributes = false });
    }

    /// <summary>
    /// Sets the signature SubFilter value independently of PAdES attribute configuration.
    /// Default is <see cref="PdfSignatureSubFilter.EtsiCadesDetached"/>.
    /// Use <see cref="PdfSignatureSubFilter.AdbePkcs7Detached"/> for PDF/A-1 compatibility
    /// or when the target validator requires the legacy subfilter.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="WithLegacyCms"/>, this method does NOT disable CAdES/PAdES attributes.
    /// The resulting signature includes full PAdES-B-B attributes (signing-certificate-v2, etc.)
    /// while using the specified SubFilter value in the PDF signature dictionary.
    /// </remarks>
    /// <param name="subFilter">The signature SubFilter value.</param>
    /// <returns>A new builder with the SubFilter configured.</returns>
    public PadesSignerBuilder WithSubFilter(PdfSignatureSubFilter subFilter)
    {
        var newField = new SignatureFieldOptions
        {
            FieldName = _options.Field.FieldName,
            SignerName = _options.Field.SignerName,
            Reason = _options.Field.Reason,
            Location = _options.Field.Location,
            ContactInfo = _options.Field.ContactInfo,
            ContentsReservedBytes = _options.Field.ContentsReservedBytes,
            SubFilter = subFilter,
            Appearance = _options.Field.Appearance,
            CertificationLevel = _options.Field.CertificationLevel,
            ExistingFieldName = _options.Field.ExistingFieldName
        };
        return With(_options with { Field = newField });
    }

    /// <summary>
    /// Registers a country/region-specific extension package (e.g., ICP-Brasil, eIDAS).
    /// Extensions provide trust anchors for validation and chain validation providers
    /// that enrich <see cref="SignatureValidationResult"/> with country-specific
    /// metadata (policy level, signer national ID, etc.).
    /// </summary>
    /// <typeparam name="T">A concrete <see cref="ICountryExtension"/> with a parameterless constructor.</typeparam>
    /// <returns>A new builder with the extension registered.</returns>
    public PadesSignerBuilder WithCountryExtension<T>()
        where T : ICountryExtension, new()
    {
        var extension = new T();
        return AddCountryExtension(extension);
    }

    /// <summary>
    /// Registers a pre-configured country extension instance for DI scenarios
    /// where the extension needs constructor-injected dependencies (HttpClient, ILogger).
    /// </summary>
    /// <param name="extension">The country extension instance.</param>
    /// <returns>A new builder with the extension registered.</returns>
    public PadesSignerBuilder WithCountryExtension(ICountryExtension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);
        return AddCountryExtension(extension);
    }

    private PadesSignerBuilder AddCountryExtension(ICountryExtension extension)
    {
        var newExtensions = new List<ICountryExtension>(_options.CountryExtensions.Count + 1);
        newExtensions.AddRange(_options.CountryExtensions);
        newExtensions.Add(extension);
        return With(_options with { CountryExtensions = newExtensions.AsReadOnly() });
    }

    /// <summary>
    /// The registered country extensions.
    /// Consumed by <see cref="Validation.PdfSignatureValidator"/> during validation.
    /// </summary>
    public IReadOnlyList<ICountryExtension> CountryExtensions => _options.CountryExtensions;

    #endregion

    #region Signing

    /// <summary>
    /// Executes the signing operation and writes the signed PDF to the output stream.
    /// </summary>
    /// <remarks>
    /// Throws <see cref="SigningException"/> when the requested level profile is
    /// configured for best-effort downgrades; use
    /// <see cref="SignWithDetailsAsync(CancellationToken)"/> in that case.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="outputStream"/> is null.</exception>
    /// <exception cref="SigningException">Certificate is missing, expired, lacks private key, the requested level cannot be produced, or the document is DocMDP-locked.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    /// <exception cref="NotSupportedException">Unsupported hash algorithm or key type.</exception>
    public async Task SignAsync(Stream outputStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outputStream);
        EnsureStrictProfile();
        await SignCoreAsync(outputStream, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Executes the signing operation and returns the signed PDF as a byte array.
    /// </summary>
    /// <remarks>
    /// Throws <see cref="SigningException"/> when the requested level profile is
    /// configured for best-effort downgrades; use
    /// <see cref="SignWithDetailsAsync(CancellationToken)"/> in that case.
    /// </remarks>
    /// <exception cref="SigningException">Certificate is missing, expired, lacks private key, the requested level cannot be produced, or the document is DocMDP-locked.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    /// <exception cref="NotSupportedException">Unsupported hash algorithm or key type.</exception>
    public async Task<byte[]> SignAsync(CancellationToken cancellationToken = default)
    {
        EnsureStrictProfile();
        using var output = new MemoryStream();
        await SignCoreAsync(output, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    /// <summary>
    /// Executes the signing operation and returns a <see cref="PadesSigningResult"/> with the
    /// signed PDF, the requested and achieved baseline levels, actual feature flags, and any
    /// non-fatal warnings. Supports explicit best-effort downgrade profiles
    /// (<see cref="SigningLevelFailureBehavior.ReturnLowerLevel"/>).
    /// </summary>
    /// <exception cref="SigningException">Certificate is missing, expired, lacks private key, the requested level cannot be produced, or the document is DocMDP-locked.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    /// <exception cref="NotSupportedException">Unsupported hash algorithm or key type.</exception>
    public async Task<PadesSigningResult> SignWithDetailsAsync(CancellationToken cancellationToken = default)
    {
        using var output = new MemoryStream();
        var result = await SignCoreAsync(output, cancellationToken).ConfigureAwait(false);
        return result with
        {
            SignedArtifact = output.ToArray()
        };
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

    private async Task<PadesSigningResult> SignCoreAsync(
        Stream outputStream,
        CancellationToken cancellationToken)
    {
        var credential = _options.Credential
            ?? throw new SigningException(
                "Certificate is required. Call WithCertificate() or WithExternalSigner() before SignAsync().",
                SigningErrorReason.CredentialMissing);
        var certificate = GetCertificate(credential);
        var chain = GetChain(credential);
        bool useExternal = credential is ExternalCredential;
        var profile = _options.Profile;

        var opId = _options.OperationId
            ?? System.Diagnostics.Activity.Current?.Id
            ?? Guid.NewGuid().ToString("N")[..8];

        ValidateSigningPrerequisites(credential, useExternal, opId);

        var logger = _options.Dependencies.Logger;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        logger.SigningStarted(opId, certificate.Subject, useExternal);

        var effectiveHash = AlgorithmInference.ResolveEffectiveHashAlgorithm(
            certificate, _options.HashAlgorithm, _options.HashAlgorithmExplicitlySet, _options.SignatureAlgorithmOid);
        var sigOid = _options.SignatureAlgorithmOid
            ?? CryptoUtility.DetectSignatureAlgorithmOid(certificate, effectiveHash);
        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(certificate, sigOid);

        var warnings = new List<SigningWarning>();
        var kuExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (kuExt is not null && !kuExt.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation))
        {
            logger.NonRepudiationMissing(certificate.Subject);
            warnings.Add(new SigningWarning(
                SigningWarningCode.NonRepudiationMissing,
                $"Certificate '{certificate.Subject}' does not declare the NonRepudiation key usage."));
        }

        var (prepareResult, signedBytes, pdfALevel) =
            await PreparePdfForSigningAsync(outputStream, effectiveHash, cancellationToken).ConfigureAwait(false);

        var cms = useExternal
            ? await BuildExternalCmsAsync(signedBytes, effectiveHash, sigOid, certificate, chain, (ExternalCredential)credential, cancellationToken).ConfigureAwait(false)
            : BuildLocalCms(signedBytes, effectiveHash, sigOid, certificate, chain);

        byte[]? timestampTokenBytes = null;
        if (profile.Timestamp is not null)
        {
            try
            {
                timestampTokenBytes = await ApplyTimestampAsync(cms, effectiveHash, profile.Timestamp, opId, cancellationToken).ConfigureAwait(false);
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

                warnings.Add(new SigningWarning(
                    SigningWarningCode.SignatureTimestampUnavailable,
                    $"Signature timestamp could not be applied: {ex.Message}"));
                warnings.Add(new SigningWarning(
                    SigningWarningCode.LevelDowngraded,
                    "The requested baseline level could not be achieved; the artifact was downgraded."));
            }

            if (timestampTokenBytes is not null)
            {
                cms = TimestampClient.EmbedTimestampInCms(cms, timestampTokenBytes);
                logger.TimestampEmbedded(opId, timestampTokenBytes.Length);
            }
        }

        await PdfSignatureWriter.FinalizeAsync(outputStream, prepareResult, cms, logger, cancellationToken).ConfigureAwait(false);

        bool hasLtvMaterial = false;
        bool hasArchiveTimestamp = false;
        if (timestampTokenBytes is not null && profile.Level >= AdesBaselineLevel.LongTerm)
        {
            (hasLtvMaterial, outputStream) = await ApplyLtvAsync(
                outputStream, timestampTokenBytes, effectiveHash, opId, warnings, cancellationToken).ConfigureAwait(false);
        }

        if (hasLtvMaterial && profile.Level >= AdesBaselineLevel.Archive)
        {
            hasArchiveTimestamp = await ApplyArchiveTimestampAsync(
                outputStream, effectiveHash, pdfALevel, profile, opId, warnings, cancellationToken).ConfigureAwait(false);
        }

        var achieved = ComputeAchievedLevel(timestampTokenBytes, hasLtvMaterial, hasArchiveTimestamp);

        logger.SigningCompleted(opId, sw.ElapsedMilliseconds, outputStream.Length);

        return new PadesSigningResult
        {
            SignedArtifact = [],
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

    private static X509Certificate2 GetCertificate(SigningCredential credential) => credential switch
    {
        LocalCredential c => c.Certificate,
        ExternalCredential c => c.Certificate,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    private static IReadOnlyList<X509Certificate2> GetChain(SigningCredential credential) => credential switch
    {
        LocalCredential c => c.Chain,
        ExternalCredential c => c.Chain,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    private static void ValidateSigningPrerequisites(SigningCredential credential, bool useExternal, string opId)
    {
        var certificate = GetCertificate(credential);
        if (!useExternal && !certificate.HasPrivateKey)
        {
            throw new SigningException(
                "Certificate must have a private key for local signing. " +
                "For A3 tokens or HSMs, use WithExternalSigner() instead of WithCertificate().",
                SigningErrorReason.PrivateKeyMissing);
        }

        if (certificate.NotAfter < DateTime.UtcNow)
        {
            throw new CertificateValidationException(
                $"Certificate '{certificate.Subject}' expired on {certificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC. Cannot sign with an expired certificate.",
                certificate.Thumbprint,
                certificate.Subject);
        }

        _ = opId;
    }

    private async Task<(PdfSignaturePrepareResult, byte[], PdfALevel?)> PreparePdfForSigningAsync(
        Stream outputStream, HashAlgorithmName effectiveHash, CancellationToken cancellationToken)
    {
        _inputPdf.Seek(0, SeekOrigin.Begin);
        if (await PdfStructureReader.IsDocMdpLockedAsync(_inputPdf, logger: _options.Dependencies.Logger, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            throw new SigningException(
                "This PDF has a certification signature (DocMDP) that prohibits further changes. Signing is not allowed.",
                SigningErrorReason.DocumentNotSignable);
        }

        _inputPdf.Seek(0, SeekOrigin.Begin);
        var pdfALevel = await PdfStructureReader.DetectPdfALevelAsync(_inputPdf, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (_options.EnforcePdfA)
        {
            var pdfAIssues = PdfAPreservationValidator.Validate(pdfALevel, _options.Field);
            var errors = pdfAIssues.Where(i => i.Severity == PdfAIssueSeverity.Error).ToList();
            if (errors.Count > 0)
            {
                throw new SigningException(
                    $"PDF/A preservation check failed: {string.Join("; ", errors.Select(e => e.Message))}",
                    SigningErrorReason.DocumentNotSignable);
            }
        }

        var prepareResult = await PdfSignatureWriter.PrepareAsync(
            _inputPdf, outputStream, _options.Field, _options.Dependencies.Logger, pdfALevel: pdfALevel,
            signingTime: _options.SigningTime, cancellationToken: cancellationToken).ConfigureAwait(false);

        var signedBytes = await PdfStructureReader.ReadSignedBytesAsync(
            outputStream, prepareResult.ByteRange, logger: _options.Dependencies.Logger, cancellationToken: cancellationToken).ConfigureAwait(false);

        return (prepareResult, signedBytes, pdfALevel);
    }

    private byte[] BuildLocalCms(
        byte[] signedBytes,
        HashAlgorithmName effectiveHash,
        string sigOid,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain)
    {
        return CmsSignatureBuilder.Build(
            signedBytes,
            certificate,
            effectiveHash,
            _options.SigningTime,
            chain,
            BuildExtraAttributes(),
            _options.PadesAttributes,
            sigOid,
            _options.Dependencies.Logger);
    }

    private async Task<byte[]> BuildExternalCmsAsync(
        byte[] signedBytes,
        HashAlgorithmName effectiveHash,
        string sigOid,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        ExternalCredential external,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string digestOid = CmsSignatureBuilder.GetDigestOid(effectiveHash);
        byte[] contentHash = CmsSignatureBuilder.ComputeHash(signedBytes, effectiveHash);
        var time = _options.SigningTime ?? DateTimeOffset.UtcNow;
        byte[] signedAttrs = CmsSignatureBuilder.BuildSignedAttributes(
            contentHash, digestOid, time, certificate, BuildExtraAttributes(), _options.PadesAttributes);

        var request = new ExternalSigningRequest(
            signedAttrs,
            effectiveHash,
            sigOid,
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
        return CmsSignatureBuilder.BuildSignedData(
            digestOid, sigOid, effectiveHash, signedAttrs, signature.ToArray(),
            certificate, allCerts,
            BuildExtraAttributes()?.Count ?? 0, _options.Dependencies.Logger);
    }

    private IReadOnlyList<CmsAttribute>? BuildExtraAttributes()
    {
        List<CmsAttribute>? extraAttributes = null;
        if (_options.Metadata is not null)
        {
            extraAttributes = [CmsAttribute.CommitmentTypeIndication(_options.Metadata.CommitmentType)];
            if (_options.Metadata.PolicyOid is not null)
            {
                extraAttributes.Add(CmsAttribute.SignaturePolicyIdentifier(
                    _options.Metadata.PolicyOid, _options.Metadata.PolicyUri));
            }
            if (_options.Metadata.ExtraAttributes is not null)
            {
                extraAttributes.AddRange(_options.Metadata.ExtraAttributes);
            }
        }

        return extraAttributes;
    }

    private async Task<byte[]?> ApplyTimestampAsync(
        byte[] cms,
        HashAlgorithmName effectiveHash,
        TimestampOptions timestampOptions,
        string opId,
        CancellationToken cancellationToken)
    {
        var logger = _options.Dependencies.Logger;
        logger.TimestampRequested(opId, timestampOptions.Endpoint.ToString());
        var tsaClient = CreateTimestampClient(timestampOptions.Endpoint.ToString(), timestampOptions.HttpClientProvider);
        return await tsaClient.GetTimestampAsync(
            TimestampClient.ExtractSignatureValue(cms), effectiveHash, cancellationToken).ConfigureAwait(false);
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

    private async Task<(bool HasLtvMaterial, Stream Output)> ApplyLtvAsync(
        Stream outputStream,
        byte[]? timestampTokenBytes,
        HashAlgorithmName effectiveHash,
        string opId,
        List<SigningWarning> warnings,
        CancellationToken cancellationToken)
    {
        var profile = _options.Profile;
        var logger = _options.Dependencies.Logger;
        logger.LtvEmbedding(opId);
        outputStream.Seek(0, SeekOrigin.Begin);
        var signedPdf = new byte[outputStream.Length];
        await outputStream.ReadExactlyAsync(signedPdf, cancellationToken).ConfigureAwait(false);

        var ltvOptions = profile.LongTermValidation!;
        var ltvProvider = ltvOptions.HttpClientProvider ?? _options.Dependencies.HttpClientProvider;
        var ltvEmbedder = _options.Dependencies.LtvEmbedder ?? new LtvEmbedder(ltvProvider, logger);

        var chain = BuildChainWithSigner();

        var ltvPdf = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, chain, timestampTokenBytes, cancellationToken).ConfigureAwait(false);

        outputStream.Seek(0, SeekOrigin.Begin);
        outputStream.SetLength(0);
        await outputStream.WriteAsync(ltvPdf, cancellationToken).ConfigureAwait(false);

        // The LTV embedder always appends certificates, so reference inequality is not proof of
        // B-LT material. Inspect the produced DSS: B-LT requires certificate values AND
        // revocation values (OCSP or CRL).
        var dss = await DssExtractor.TryReadFullDssDataAsync(outputStream, cancellationToken, logger).ConfigureAwait(false);
        bool dssEmbedded = dss.GlobalCerts.Count > 0 && (dss.GlobalCrls.Count > 0 || dss.GlobalOcsps.Count > 0);
        if (!dssEmbedded)
        {
            logger.LtvEmbeddingFailed(opId);
            if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
            {
                throw new SigningException(
                    "LTV was requested but no revocation data could be collected — DSS was not embedded. " +
                    "The requested B-LT/B-LTA level cannot be produced.",
                    SigningErrorReason.LevelNotAchievable);
            }

            warnings.Add(new SigningWarning(
                SigningWarningCode.LongTermValidationMaterialUnavailable,
                "LTV was requested but no revocation data could be collected — DSS not embedded."));
            warnings.Add(new SigningWarning(
                SigningWarningCode.LevelDowngraded,
                "The requested baseline level could not be achieved; the artifact was downgraded."));
        }

        return (dssEmbedded, outputStream);
    }

    private async Task<bool> ApplyArchiveTimestampAsync(
        Stream outputStream,
        HashAlgorithmName effectiveHash,
        PdfALevel? pdfALevel,
        AdesBaselineProfile profile,
        string opId,
        List<SigningWarning> warnings,
        CancellationToken cancellationToken)
    {
        var logger = _options.Dependencies.Logger;
        var archiveOptions = profile.ArchiveTimestamp;
        var timestampOptions = profile.Timestamp!;
        var endpoint = archiveOptions?.Endpoint ?? timestampOptions.Endpoint;
        var scopedProvider = archiveOptions?.HttpClientProvider ?? timestampOptions.HttpClientProvider;

        logger.ArchivalTimestampAppending(opId, endpoint.ToString());
        try
        {
            outputStream.Seek(0, SeekOrigin.Begin);
            var signedPdf = new byte[outputStream.Length];
            await outputStream.ReadExactlyAsync(signedPdf, cancellationToken).ConfigureAwait(false);

            var provider = scopedProvider ?? _options.Dependencies.HttpClientProvider;
            var ltvPdf = await DocTimeStampWriter.AppendDocTimeStampAsync(
                signedPdf, endpoint.ToString(), provider.GetClient(),
                effectiveHash, pdfALevel: pdfALevel,
                tsaFactory: _options.Dependencies.TsaFactory,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            outputStream.Seek(0, SeekOrigin.Begin);
            outputStream.SetLength(0);
            await outputStream.WriteAsync(ltvPdf, cancellationToken).ConfigureAwait(false);

            logger.ArchivalTimestampComplete(opId);
            return true;
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

            warnings.Add(new SigningWarning(
                SigningWarningCode.ArchiveTimestampUnavailable,
                $"Archive timestamp could not be applied: {ex.Message}"));
            warnings.Add(new SigningWarning(
                SigningWarningCode.LevelDowngraded,
                "The requested baseline level could not be achieved; the artifact was downgraded."));
            return false;
        }
    }

    private List<X509Certificate2> BuildChainWithSigner()
    {
        var credential = _options.Credential!;
        var certificate = GetCertificate(credential);
        var configuredChain = GetChain(credential);
        var chain = new List<X509Certificate2>(configuredChain.Count + 1);
        if (!configuredChain.Any(c => c.Thumbprint == certificate.Thumbprint))
        {
            chain.Add(certificate);
        }

        chain.AddRange(configuredChain);
        return chain;
    }

    #endregion

    #region Builder helpers

    private PadesSignerBuilder WithCredential(SigningCredential credential) =>
        With(_options with { Credential = credential });

    private PadesSignerBuilder With(PadesSigningOptions options) =>
        new(_inputPdf, options);

    private static IReadOnlyList<X509Certificate2> CopyChain(IReadOnlyList<X509Certificate2> chain) =>
        chain.ToList().AsReadOnly();

    private SignatureFieldOptions CloneField(
        string? fieldName = null,
        string? signerName = null,
        string? reason = null,
        string? location = null,
        string? contactInfo = null,
        SignatureAppearance? appearance = null,
        CertificationLevel? certificationLevel = null,
        string? existingFieldName = null)
    {
        var current = _options.Field;
        return new SignatureFieldOptions
        {
            FieldName = fieldName ?? current.FieldName,
            SignerName = signerName ?? current.SignerName,
            Reason = reason ?? current.Reason,
            Location = location ?? current.Location,
            ContactInfo = contactInfo ?? current.ContactInfo,
            ContentsReservedBytes = current.ContentsReservedBytes,
            SubFilter = current.SubFilter,
            Appearance = appearance ?? current.Appearance,
            CertificationLevel = certificationLevel ?? current.CertificationLevel,
            ExistingFieldName = existingFieldName ?? current.ExistingFieldName
        };
    }

    #endregion
}
