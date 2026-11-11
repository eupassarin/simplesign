using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Internal;

namespace SimpleSign.PAdES;

/// <summary>
/// Immutable builder that accumulates PAdES signing configuration.
/// Each method returns a new instance — no shared mutable state.
/// </summary>
public sealed class PadesSignerBuilder
{
    private readonly Stream _inputPdf;
    private readonly PadesSigningOptions _options;
    private readonly PadesExecutionGate? _executionGate;

    internal PadesSignerBuilder(Stream inputPdf, bool singleExecution = true, ILogger? logger = null)
    {
        _inputPdf = inputPdf;
        _executionGate = singleExecution ? new PadesExecutionGate() : null;
        _options = new PadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Field: new SignatureFieldOptions(),
            Metadata: null,
            EnforcePdfA: false,
            OperationId: null,
            Profile: AdesBaselineProfile.Basic(),
            CountryExtensions: [],
            Dependencies: new PadesDependencies(null, null, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    internal PadesSignerBuilder(Stream inputPdf, ILogger? logger)
        : this(inputPdf, singleExecution: true, logger)
    {
    }

    internal PadesSignerBuilder(
        Stream inputPdf,
        ITimestampClientFactory tsaFactory,
        ILtvEmbedder ltvEmbedder,
        ILogger? logger = null)
    {
        _inputPdf = inputPdf;
        _executionGate = new PadesExecutionGate();
        _options = new PadesSigningOptions(
            Credential: null,
            HashAlgorithm: HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet: false,
            SignatureAlgorithmOid: null,
            SigningTime: null,
            Field: new SignatureFieldOptions(),
            Metadata: null,
            EnforcePdfA: false,
            OperationId: null,
            Profile: AdesBaselineProfile.Basic(),
            CountryExtensions: [],
            Dependencies: new PadesDependencies(tsaFactory, ltvEmbedder, logger ?? NullLogger.Instance, DefaultHttpClientProvider.Instance));
    }

    private PadesSignerBuilder(Stream inputPdf, PadesSigningOptions options, PadesExecutionGate? executionGate)
    {
        _inputPdf = inputPdf;
        _options = options;
        _executionGate = executionGate;
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

    /// <summary>
    /// Loads a PKCS#12 (.pfx / .p12) file and uses it for local signing: the first certificate
    /// with a private key signs, and the other certificates in the file are embedded as its chain.
    /// </summary>
    /// <remarks>
    /// The loaded certificates are owned by the returned builder and are not disposed by it.
    /// When you need to control their lifetime, load them yourself and call
    /// <see cref="WithCertificate(X509Certificate2, IReadOnlyList{X509Certificate2})"/>.
    /// </remarks>
    /// <param name="pfxPath">Path to the PKCS#12 file.</param>
    /// <param name="password">The file's password, or <see langword="null"/> when it has none.</param>
    /// <returns>A new builder with the local credential configured.</returns>
    /// <exception cref="ArgumentException"><paramref name="pfxPath"/> is null or whitespace, or the file has no certificate with a private key.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The password is wrong or the file is not a valid PKCS#12.</exception>
    public PadesSignerBuilder WithCertificateFile(string pfxPath, string? password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pfxPath);
        var (signer, chain) = CertificateLoader.LoadSigningCredentialFromFile(pfxPath, password);
        return WithCredential(new LocalCredential(signer, chain));
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

    /// <summary>
    /// Sets the checks run before signing, read from a JSON signing policy (<see cref="SigningPolicy.Load"/>):
    /// validity of the chain, key usage, key size, digest algorithm and, when <c>NotRevoked</c> is not IGNORE, the
    /// revocation of the chain. Default: <see cref="SigningPolicy.Default"/>.
    /// </summary>
    /// <param name="policy">The signing policy.</param>
    /// <returns>A new builder with the policy configured.</returns>
    public PadesSignerBuilder WithSigningPolicy(SigningPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return With(_options with { SigningPolicy = policy });
    }

    /// <summary>
    /// Records every signing operation of this builder, signed or refused, with <paramref name="sink"/> (a trail of
    /// the signatures generated). The record is written before the signer returns; a failing sink fails the operation.
    /// </summary>
    /// <param name="sink">The audit sink (e.g. <see cref="JsonLinesAuditSink"/>).</param>
    /// <returns>A new builder with the sink configured.</returns>
    public PadesSignerBuilder WithAuditSink(ISignatureAuditSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        return With(_options with { AuditSink = sink });
    }

    /// <summary>
    /// Adds trust anchors for the checks made before signing: the signing certificate must chain to one of them when
    /// the signing policy's <c>SigningCertificate/ProspectiveCertificateChain</c> is not IGNORE, and they complete a
    /// chain given without its root for the revocation check. The anchors of the country extensions
    /// (<see cref="WithCountryExtension(ICountryExtension)"/>) are used too.
    /// </summary>
    /// <param name="providers">The trust anchor providers (e.g. <c>DirectoryTrustAnchorProvider</c>, <c>TrustedList</c>).</param>
    /// <returns>A new builder with the anchors added.</returns>
    public PadesSignerBuilder WithTrustAnchors(params ITrustAnchorProvider[] providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        return With(_options with { TrustAnchors = [.. _options.TrustAnchors, .. providers] });
    }

    /// <summary>Sets the checker used for the revocation check of the signing policy (<c>NotRevoked</c>, <c>RevocationDataAvailable</c>).</summary>
    /// <param name="checker">The chain revocation checker.</param>
    /// <returns>A new builder with the checker configured.</returns>
    public PadesSignerBuilder WithChainRevocationChecker(SimpleSign.Core.Revocation.IChainRevocationChecker checker)
    {
        ArgumentNullException.ThrowIfNull(checker);
        return With(_options with { Dependencies = _options.Dependencies with { ChainRevocationChecker = checker } });
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
    /// Replaces the complete PDF signature-field configuration.
    /// </summary>
    /// <param name="options">The complete field configuration to snapshot.</param>
    /// <returns>A new builder with the supplied field configuration.</returns>
    /// <remarks>
    /// Use this method when an optional field value previously configured on a builder must be
    /// cleared. Unlike the convenience methods, this operation replaces rather than merges
    /// field state.
    /// </remarks>
    public PadesSignerBuilder WithFieldOptions(SignatureFieldOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.FieldName);
        return With(_options with { Field = SnapshotField(options) });
    }

    /// <summary>
    /// Configures generic signer metadata for the signature.
    /// Replaces signer, reason, location, and contact field values; omitted values clear earlier metadata.
    /// Use this for country-agnostic signing with structured metadata.
    /// For Brazil-specific signing, use <c>WithAdvancedSignature</c> from SimpleSign.Brazil.
    /// </summary>
    /// <param name="metadata">The signer metadata.</param>
    /// <returns>A new builder with the metadata configured.</returns>
    public PadesSignerBuilder WithMetadata(SignatureMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        string? location = metadata.Location ?? metadata.InstitutionName;

        string? contactInfo;
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
            contactInfo = contactParts.Count == 0 ? null : string.Join(" | ", contactParts);
        }

        var currentField = _options.Field;
        var updatedField = new SignatureFieldOptions
        {
            FieldName = currentField.FieldName,
            SignerName = metadata.SignerName,
            Reason = metadata.Reason,
            Location = location,
            ContactInfo = contactInfo,
            ContentsReservedBytes = currentField.ContentsReservedBytes,
            SubFilter = currentField.SubFilter,
            Appearance = currentField.Appearance,
            CertificationLevel = currentField.CertificationLevel,
            ExistingFieldName = currentField.ExistingFieldName
        };

        return With(_options with { Field = updatedField, Metadata = CopyMetadata(metadata) });
    }

    /// <summary>
    /// Sets the signature policy, with its hash, as the signature-policy-identifier signed
    /// attribute (ETSI EN 319 122-1 §5.2.9) — e.g. an ICP-Brasil AD-RB/AD-RT policy.
    /// </summary>
    /// <param name="policy">The policy OID, hash and optional URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public PadesSignerBuilder WithSignaturePolicy(SignaturePolicyReference policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return With(_options with { SignaturePolicy = policy });
    }

    /// <summary>
    /// Sets an entry of the PDF document information dictionary (ISO 32000-1 §14.3.3) in the
    /// signing revision, so the signature covers it. Existing entries are kept; a key set
    /// twice keeps the last value. Not supported when signing an existing field.
    /// </summary>
    /// <param name="key">The key, without the leading slash (e.g. <c>Title</c>, or an OID).</param>
    /// <param name="value">The text value.</param>
    /// <returns>A new builder with the entry configured.</returns>
    /// <exception cref="ArgumentException">The key is empty or not a valid PDF name.</exception>
    public PadesSignerBuilder WithDocumentInfo(string key, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(value);
        if (key.Any(c => c <= ' ' || c > '~' || "()<>[]{}/%#".Contains(c, StringComparison.Ordinal)))
        {
            throw new ArgumentException("The key must be printable ASCII without PDF delimiters.", nameof(key));
        }

        var info = new Dictionary<string, string>(_options.DocumentInfo ?? new Dictionary<string, string>(), StringComparer.Ordinal)
        {
            [key] = value,
        };
        return With(_options with { DocumentInfo = info });
    }

    /// <summary>
    /// Adds a visual appearance (stamp) to the signature on a specific page.
    /// The stamp displays the signer name, date/time, and other configured metadata.
    /// </summary>
    /// <param name="appearance">The visual appearance configuration.</param>
    /// <returns>A new builder with the appearance configured.</returns>
    public PadesSignerBuilder WithAppearance(SignatureAppearance appearance)
    {
        ArgumentNullException.ThrowIfNull(appearance);
        return With(_options with { Field = CloneField(appearance: appearance.Snapshot()) });
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
    /// Adds extra streams to the Document Security Store written for B-LT/B-LTA: each one is
    /// listed in the DSS array <see cref="PdfDssArtifact.DssKey"/> and referenced from this
    /// signature's VRI as <see cref="PdfDssArtifact.VriKey"/>. The ICP-Brasil AD-RA policy uses
    /// this for its policy artifacts. Needs a B-LT or B-LTA profile.
    /// </summary>
    /// <param name="artifacts">The artifacts.</param>
    /// <returns>A new builder with the artifacts configured.</returns>
    /// <exception cref="ArgumentException">An artifact key is not usable.</exception>
    public PadesSignerBuilder WithDssArtifacts(IEnumerable<PdfDssArtifact> artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        var list = artifacts.ToList();
        foreach (var artifact in list)
        {
            ArgumentNullException.ThrowIfNull(artifact, nameof(artifacts));
            artifact.Validate();
        }

        return With(_options with { DssArtifacts = [.. _options.DssArtifacts, .. list] });
    }

    /// <summary>
    /// Sets the signature SubFilter value independently of PAdES attribute configuration.
    /// Default is <see cref="PdfSignatureSubFilter.EtsiCadesDetached"/>.
    /// Use <see cref="PdfSignatureSubFilter.AdbePkcs7Detached"/> for PDF/A-1 compatibility
    /// or when the target validator requires the legacy subfilter.
    /// </summary>
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
    /// Extensions provide trust anchors (for validation, and for the trust check made before signing when the
    /// signing policy asks for it) and chain validation providers
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
        BaselineSigning.EnsureStrictProfile(_options.Profile);
        EnterExecution();
        using var stagedOutput = new MemoryStream();
        await SignCoreAsync(stagedOutput, cancellationToken).ConfigureAwait(false);
        stagedOutput.Seek(0, SeekOrigin.Begin);
        await stagedOutput.CopyToAsync(outputStream, cancellationToken).ConfigureAwait(false);
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
        BaselineSigning.EnsureStrictProfile(_options.Profile);
        EnterExecution();
        using var output = new MemoryStream();
        await SignAuditedAsync(output, cancellationToken).ConfigureAwait(false);
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
        EnterExecution();
        using var output = new MemoryStream();
        var result = await SignAuditedAsync(output, cancellationToken).ConfigureAwait(false);
        return result with
        {
            SignedArtifact = output.ToArray()
        };
    }

    private Task<PadesSigningResult> SignAuditedAsync(MemoryStream output, CancellationToken cancellationToken) =>
        SignatureAudit.RunAsync(
            _options.AuditSink,
            () => SignatureAuditEvent.Start(
                "PAdES", _options.OperationId, _options.Profile.Level, SignerCertificate, _options.SigningPolicy,
                _inputPdf is MemoryStream input && input.TryGetBuffer(out var buffer) ? buffer.AsSpan() : default),
            () => SignCoreAsync(output, cancellationToken),
            result => (output.ToArray(), result.AchievedLevel),
            cancellationToken);

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
        if (_options.DssArtifacts.Count > 0 && profile.Level < AdesBaselineLevel.LongTerm)
        {
            throw new SigningException(
                "DSS artifacts are written with the long-term validation data: use a B-LT or B-LTA profile.",
                SigningErrorReason.LevelNotAchievable);
        }

        var opId = _options.OperationId
            ?? System.Diagnostics.Activity.Current?.Id
            ?? Guid.NewGuid().ToString("N")[..8];

        ValidateSigningPrerequisites(credential, useExternal);
        var warnings = new List<SigningWarning>();
        await SignerAcceptance.EnsureSignerAcceptableAsync(
            certificate, chain, _options.SigningPolicy, _options.AllTrustAnchors, _options.Dependencies.ChainRevocationChecker,
            _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger, warnings, cancellationToken).ConfigureAwait(false);

        var logger = _options.Dependencies.Logger;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        logger.SigningStarted(opId, certificate.Subject, certificate.SerialNumber, useExternal);

        if (_options.HashAlgorithmExplicitlySet)
        {
            SignerAcceptance.EnsureHashAllowed(_options.HashAlgorithm, _options.SigningPolicy);
        }

        var resolvedAlgorithm = SigningAlgorithmResolver.Resolve(
            certificate, _options.HashAlgorithm, _options.HashAlgorithmExplicitlySet, _options.SignatureAlgorithmOid);
        var effectiveHash = resolvedAlgorithm.HashAlgorithm;
        SignerAcceptance.EnsureHashAllowed(effectiveHash, _options.SigningPolicy, warnings, logger);
        var sigOid = resolvedAlgorithm.SignatureAlgorithmOid;
        logger.AlgorithmResolved(opId, effectiveHash.Name ?? "?", sigOid, _options.Profile.Level.ToString(), _options.Field.SubFilter.ToString());
        logger.FieldConfigured(opId, _options.Field.ExistingFieldName ?? _options.Field.FieldName,
            _options.Field.ExistingFieldName is not null, _options.Field.Appearance is not null,
            _options.Field.CertificationLevel?.ToString() ?? "none");

        var kuExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (kuExt is not null && !kuExt.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation))
        {
            logger.NonRepudiationMissing(certificate.Subject);
            warnings.Add(new SigningWarning(
                SigningWarningCode.NonRepudiationMissing,
                $"Certificate '{certificate.Subject}' does not declare the NonRepudiation key usage."));
        }

        var (prepareResult, signedBytes, pdfALevel) =
            await PreparePdfForSigningAsync(outputStream, opId, cancellationToken).ConfigureAwait(false);

        var cms = useExternal
            ? await BuildExternalCmsAsync(signedBytes, effectiveHash, sigOid, resolvedAlgorithm.RsaPssParameters, certificate, chain, (ExternalCredential)credential, cancellationToken).ConfigureAwait(false)
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
            catch (Exception ex) when (BaselineSigning.IsTimestampRefusal(ex))
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

                BaselineSigning.AddDowngradeWarnings(
                    warnings, SigningWarningCode.SignatureTimestampUnavailable,
                    $"Signature timestamp could not be applied: {ex.Message}");
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
                outputStream, timestampTokenBytes, opId, warnings, cancellationToken).ConfigureAwait(false);
        }

        if (hasLtvMaterial && profile.Level == AdesBaselineLevel.LongTerm)
        {
            logger.LtvEmbeddedNoArchival(opId);
        }

        if (hasLtvMaterial && profile.Level >= AdesBaselineLevel.Archive)
        {
            hasArchiveTimestamp = await ApplyArchiveTimestampAsync(
                outputStream, effectiveHash, pdfALevel, profile, opId, warnings, cancellationToken).ConfigureAwait(false);
        }

        List<X509Certificate2>? requiredLtvCertificates = null;
        List<X509Certificate2>? disposableTsaCertificates = null;
        if (hasLtvMaterial)
        {
            requiredLtvCertificates = BuildRequiredLtvCertificates(timestampTokenBytes, out disposableTsaCertificates);
        }

        (bool BaseSignatureValid, bool HasTimestamp, bool HasLtvMaterial, bool HasArchiveTimestamp) artifactFacts;
        try
        {
            artifactFacts = await InspectProducedArtifactAsync(
                outputStream,
                timestampTokenBytes,
                hasLtvMaterial,
                requiredLtvCertificates,
                hasArchiveTimestamp,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            DisposeCertificates(disposableTsaCertificates);
        }
        if (!artifactFacts.BaseSignatureValid)
        {
            throw new SigningException(
                "The completed PDF signature or signed content failed read-back verification.",
                SigningErrorReason.Unspecified);
        }

        if (timestampTokenBytes is not null && !artifactFacts.HasTimestamp)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.SignatureTimestampUnavailable,
                "The produced PDF does not contain the requested signature timestamp token.");
        }

        if (hasLtvMaterial && !artifactFacts.HasLtvMaterial)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.LongTermValidationMaterialUnavailable,
                "The produced PDF does not contain complete DSS validation material.");
        }

        if (hasArchiveTimestamp && !artifactFacts.HasArchiveTimestamp)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.ArchiveTimestampUnavailable,
                "The produced PDF does not contain the requested document timestamp.");
        }

        var achieved = BaselineSigning.AchievedLevel(
            artifactFacts.HasTimestamp, artifactFacts.HasLtvMaterial, artifactFacts.HasArchiveTimestamp);

        logger.ReadBackVerified(opId, artifactFacts.BaseSignatureValid, artifactFacts.HasTimestamp,
            artifactFacts.HasLtvMaterial, artifactFacts.HasArchiveTimestamp, achieved.ToString());
        logger.SigningCompleted(opId, sw.ElapsedMilliseconds, outputStream.Length);

        return new PadesSigningResult
        {
            SignedArtifact = [],
            RequestedLevel = profile.Level,
            AchievedLevel = achieved,
            HasSignatureTimestamp = artifactFacts.HasTimestamp,
            HasLongTermValidationMaterial = artifactFacts.HasLtvMaterial,
            HasArchiveTimestamp = artifactFacts.HasArchiveTimestamp,
            Warnings = warnings.AsReadOnly()
        };
    }

    private static async Task<(bool BaseSignatureValid, bool HasTimestamp, bool HasLtvMaterial, bool HasArchiveTimestamp)>
        InspectProducedArtifactAsync(
            Stream outputStream,
            byte[]? expectedTimestampToken,
            bool expectedLtvMaterial,
            IReadOnlyList<X509Certificate2>? requiredLtvCertificates,
            bool expectedArchiveTimestamp,
            CancellationToken cancellationToken)
    {
        try
        {
            outputStream.Seek(0, SeekOrigin.Begin);
            var artifactBytes = new byte[outputStream.Length];
            await outputStream.ReadExactlyAsync(artifactBytes, cancellationToken).ConfigureAwait(false);
            outputStream.Seek(0, SeekOrigin.Begin);
            PdfInspectionResult inspection = await PdfSignatureInspector.InspectAsync(
                outputStream, cancellationToken: cancellationToken).ConfigureAwait(false);
            // Incremental updates preserve prior signatures. The signature with the latest
            // /Contents offset is the one this terminal operation just appended.
            SignatureFieldInfo? signature = inspection.Signatures
                .Where(field => !field.IsDocumentTimestamp)
                .OrderByDescending(field => field.ByteRange.ContentsOffset)
                .FirstOrDefault();
            using var validationStream = new MemoryStream(artifactBytes, writable: false);
            var validator = new PdfSignatureValidator(new ValidationOptions
            {
                CheckRevocation = false,
                TrustSystemRoots = false
            });
            var validationResults = await validator.ValidateAsync(
                validationStream, cancellationToken: cancellationToken).ConfigureAwait(false);
            var validatedSignature = signature is null ? null : validationResults.LastOrDefault(
                result => !result.IsDocumentTimestamp && result.FieldName == signature.FieldName);
            bool baseSignatureValid = validatedSignature is not null &&
                validatedSignature.IsSignatureValid && validatedSignature.IsIntegrityValid;
            CmsSignedData? cms = signature is null ? null : CmsParser.Parse(signature.CmsRawData.ToArray());
            bool hasTimestamp = baseSignatureValid && expectedTimestampToken is not null &&
                validatedSignature?.HasValidTimestamp == true && cms?.SignatureTimestampToken is not null &&
                CryptographicOperations.FixedTimeEquals(cms.SignatureTimestampToken, expectedTimestampToken);
            bool hasLtvMaterial = false;
            if (hasTimestamp && expectedLtvMaterial && requiredLtvCertificates is not null)
            {
                using var dssStream = new MemoryStream(artifactBytes, writable: false);
                var dss = await DssExtractor.TryReadFullDssDataAsync(dssStream, cancellationToken).ConfigureAwait(false);
                hasLtvMaterial = LtvEmbedder.HasCompleteEvidence(dss, requiredLtvCertificates);
            }
            bool hasArchiveTimestamp = hasLtvMaterial && expectedArchiveTimestamp && inspection.Signatures
                .Where(field => field.IsDocumentTimestamp)
                .Where(field => signature is not null && field.ByteRange.ContentsOffset > signature.ByteRange.ContentsOffset)
                .Any(field => validationResults.Any(result =>
                    result.IsDocumentTimestamp && result.FieldName == field.FieldName &&
                    result.IsSignatureValid && result.IsIntegrityValid) &&
                    HasValidDocumentTimestampBinding(field, artifactBytes));
            return (baseSignatureValid, hasTimestamp, hasLtvMaterial, hasArchiveTimestamp);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return (false, false, false, false);
        }
        finally
        {
            if (outputStream.CanSeek)
            {
                outputStream.Seek(0, SeekOrigin.End);
            }
        }
    }

    private static bool HasValidDocumentTimestampBinding(SignatureFieldInfo field, byte[] artifactBytes)
    {
        try
        {
            CmsSignedData timestamp = CmsParser.Parse(field.CmsRawData.ToArray());
            HashAlgorithmName hashAlgorithm = timestamp.TstMessageImprintHashAlgOid switch
            {
                Oids.Sha256 => HashAlgorithmName.SHA256,
                Oids.Sha384 => HashAlgorithmName.SHA384,
                Oids.Sha512 => HashAlgorithmName.SHA512,
                Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
                Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
                Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
                _ => throw new InvalidOperationException("DocTimeStamp uses an unsupported message-imprint algorithm."),
            };
            var byteRange = field.ByteRange;
            if (!byteRange.IsValid || byteRange.Offset1 != 0 || byteRange.Offset2 + byteRange.Length2 > artifactBytes.Length)
            {
                return false;
            }

            var input = new byte[byteRange.Length1 + byteRange.Length2];
            artifactBytes.AsSpan(0, (int)byteRange.Length1).CopyTo(input);
            artifactBytes.AsSpan((int)byteRange.Offset2, (int)byteRange.Length2)
                .CopyTo(input.AsSpan((int)byteRange.Length1));
            TimestampClient.ValidateTimestampToken(field.CmsRawData.ToArray(), input, hashAlgorithm);
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimestampException or CryptographicException)
        {
            return false;
        }
    }

    /// <summary>The signer certificate given to WithCertificate or WithExternalSigner, or <see langword="null"/> before either is called. Extensions read it to pick policies.</summary>
    public X509Certificate2? SignerCertificate => _options.Credential is { } credential ? GetCertificate(credential) : null;

    /// <summary>The certificate chain given with the signer certificate (empty when none was given).</summary>
    public IReadOnlyList<X509Certificate2> SignerChain => _options.Credential is { } credential ? GetChain(credential) : [];

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

    private static void ValidateSigningPrerequisites(SigningCredential credential, bool useExternal)
    {
        var certificate = GetCertificate(credential);
        if (!useExternal && !certificate.HasPrivateKey)
        {
            throw new SigningException(
                "Certificate must have a private key for local signing. " +
                "For A3 tokens or HSMs, use WithExternalSigner() instead of WithCertificate().",
                SigningErrorReason.PrivateKeyMissing);
        }

        BaselineSigning.EnsureCertificateValidNow(certificate);
    }

    private async Task<(PdfSignaturePrepareResult, byte[], PdfALevel?)> PreparePdfForSigningAsync(
        Stream outputStream, string opId, CancellationToken cancellationToken)
    {
        _inputPdf.Seek(0, SeekOrigin.Begin);
        if (await PdfStructureReader.IsDocMdpLockedAsync(_inputPdf, logger: _options.Dependencies.Logger, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            throw new SigningException(
                "This PDF has a certification signature (DocMDP) that prohibits further changes. Signing is not allowed.",
                SigningErrorReason.DocumentNotSignable);
        }

        if (_options.Field.CertificationLevel is not null)
        {
            _inputPdf.Seek(0, SeekOrigin.Begin);
            var fields = await PdfStructureReader.ReadSignatureFieldsAsync(_inputPdf, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (fields.Any(f => f.IsSigned))
            {
                throw new SigningException(
                    "Only the first signature of a document can certify it (DocMDP): this PDF is already signed. Sign without AsCertification().",
                    SigningErrorReason.DocumentNotSignable);
            }
        }

        _inputPdf.Seek(0, SeekOrigin.Begin);
        var pdfALevel = await PdfStructureReader.DetectPdfALevelAsync(_inputPdf, cancellationToken: cancellationToken).ConfigureAwait(false);

        _options.Dependencies.Logger.PdfALevelDetected(
            opId, pdfALevel.ToString(), _options.EnforcePdfA);
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
            _inputPdf, outputStream, _options.Field, _options.Dependencies.Logger, pdfALevel,
            _options.SigningTime, _options.DocumentInfo, cancellationToken).ConfigureAwait(false);

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
            padesAttributes: true,
            sigOid,
            _options.Dependencies.Logger);
    }

    private async Task<byte[]> BuildExternalCmsAsync(
        byte[] signedBytes,
        HashAlgorithmName effectiveHash,
        string sigOid,
        RsaPssParameters? rsaPssParameters,
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
            contentHash, digestOid, time, certificate, BuildExtraAttributes(), padesAttributes: true);

        var request = new ExternalSigningRequest(
            signedAttrs,
            effectiveHash,
            sigOid,
            ExternalSigningPayloadKind.CmsSignedAttributes,
            _options.OperationId,
            rsaPssParameters);
        ReadOnlyMemory<byte> signature = await BaselineSigning
            .SignExternallyAsync(external.Signer, request, certificate, cancellationToken).ConfigureAwait(false);

        List<X509Certificate2> allCerts = [certificate, .. chain];
        return CmsSignatureBuilder.BuildSignedData(
            digestOid, sigOid, effectiveHash, signedAttrs, signature.ToArray(),
            certificate, allCerts,
            BuildExtraAttributes()?.Count ?? 0, _options.Dependencies.Logger);
    }

    private IReadOnlyList<CmsAttribute>? BuildExtraAttributes()
    {
        var extraAttributes = new List<CmsAttribute>();
        if (_options.Metadata is not null)
        {
            extraAttributes.Add(CmsAttribute.CommitmentTypeIndication(_options.Metadata.CommitmentType));
            if (_options.Metadata.PolicyOid is not null && _options.SignaturePolicy is null)
            {
                extraAttributes.Add(CmsAttribute.SignaturePolicyIdentifier(
                    _options.Metadata.PolicyOid, _options.Metadata.PolicyUri));
            }
            if (_options.Metadata.ExtraAttributes is not null)
            {
                extraAttributes.AddRange(_options.Metadata.ExtraAttributes);
            }
        }

        if (_options.SignaturePolicy is not null)
        {
            extraAttributes.Add(CmsAttribute.SignaturePolicyIdentifier(_options.SignaturePolicy));
        }

        // A signed attribute may appear once (RFC 5652 §5.3): the last one of a type wins.
        var distinct = extraAttributes
            .GroupBy(a => a.Oid, StringComparer.Ordinal)
            .Select(g => g.Last())
            .ToList();
        return distinct.Count > 0 ? distinct : null;
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
        var tsaClient = CreateTimestampClient(timestampOptions);
        byte[] signatureValue = TimestampClient.ExtractSignatureValue(cms);
        byte[] token = await tsaClient.GetTimestampAsync(signatureValue, effectiveHash, cancellationToken).ConfigureAwait(false);
        TimestampClient.ValidateTimestampToken(token, signatureValue, effectiveHash);
        return token;
    }

    private ITimestampClient CreateTimestampClient(TimestampOptions timestampOptions) =>
        new TimestampAcceptance(
            _options.SigningPolicy, _options.AllTrustAnchors, _options.Dependencies.ChainRevocationChecker,
            _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger)
        .Wrap(
            BaselineSigning.CreateTimestampClient(
                timestampOptions, _options.Dependencies.TsaFactory, _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger),
            timestampOptions);

    private async Task<(bool HasLtvMaterial, Stream Output)> ApplyLtvAsync(
        Stream outputStream,
        byte[]? timestampTokenBytes,
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
        var ltvEmbedder = _options.Dependencies.LtvEmbedder
            ?? new LtvEmbedder(ltvProvider, logger)
            {
                RevocationPreference = ltvOptions.RevocationPreference,
                ClockSkewTolerance = ltvOptions.ClockSkewTolerance,
            };

        var chain = BuildChainWithSigner();

        var ltvPdf = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, chain, timestampTokenBytes, _options.DssArtifacts, ltvOptions, cancellationToken).ConfigureAwait(false);

        outputStream.Seek(0, SeekOrigin.Begin);
        outputStream.SetLength(0);
        await outputStream.WriteAsync(ltvPdf, cancellationToken).ConfigureAwait(false);

        // The LTV embedder always appends certificates, so reference inequality is not proof of
        // B-LT material. Inspect the produced DSS: B-LT requires certificate values AND
        // revocation values (OCSP or CRL).
        var dss = await DssExtractor.TryReadFullDssDataAsync(outputStream, cancellationToken, logger).ConfigureAwait(false);
        var requiredCertificates = BuildRequiredLtvCertificates(timestampTokenBytes, out var disposableTsaCertificates);
        bool dssEmbedded;
        try
        {
            dssEmbedded = dss.GlobalCerts.Count > 0 &&
                LtvEmbedder.HasCompleteEvidence(dss, requiredCertificates);
        }
        finally
        {
            DisposeCertificates(disposableTsaCertificates);
        }
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

            BaselineSigning.AddDowngradeWarnings(
                warnings, SigningWarningCode.LongTermValidationMaterialUnavailable,
                "LTV was requested but no revocation data could be collected — DSS not embedded.");
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
        // The archive TSA inherits the signature TSA's credentials and transport when it has no
        // endpoint of its own; with its own endpoint it uses its own credentials.
        var effective = profile.ArchiveTimestamp?.Resolve(profile.Timestamp!) ?? profile.Timestamp!;
        var endpoint = effective.Endpoint;
        var scopedProvider = effective.HttpClientProvider;

        logger.ArchivalTimestampAppending(opId, endpoint.ToString());
        try
        {
            outputStream.Seek(0, SeekOrigin.Begin);
            var signedPdf = new byte[outputStream.Length];
            await outputStream.ReadExactlyAsync(signedPdf, cancellationToken).ConfigureAwait(false);

            var provider = scopedProvider ?? _options.Dependencies.HttpClientProvider;
            var ltvPdf = await DocTimeStampWriter.AppendDocTimeStampAsync(
                signedPdf, endpoint.ToString(), provider.GetClient(), logger,
                effectiveHash, pdfALevel: pdfALevel,
                tsaFactory: new FixedTimestampClientFactory(CreateTimestampClient(effective)),
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
        catch (Exception ex) when (BaselineSigning.IsTimestampRefusal(ex))
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

            BaselineSigning.AddDowngradeWarnings(
                warnings, SigningWarningCode.ArchiveTimestampUnavailable,
                $"Archive timestamp could not be applied: {ex.Message}");
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

    private List<X509Certificate2> BuildRequiredLtvCertificates(
        byte[]? timestampTokenBytes,
        out List<X509Certificate2> disposableTsaCertificates)
    {
        var requiredCertificates = BuildChainWithSigner();
        disposableTsaCertificates = [];
        if (timestampTokenBytes is null)
        {
            return requiredCertificates;
        }

        foreach (var tsaCertificate in TsaCertificateExtractor.ExtractCertificates(timestampTokenBytes))
        {
            if (requiredCertificates.Any(certificate => certificate.Thumbprint == tsaCertificate.Thumbprint))
            {
                tsaCertificate.Dispose();
                continue;
            }

            requiredCertificates.Add(tsaCertificate);
            disposableTsaCertificates.Add(tsaCertificate);
        }

        return requiredCertificates;
    }

    private static void DisposeCertificates(IEnumerable<X509Certificate2>? certificates)
    {
        if (certificates is null)
        {
            return;
        }

        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }

    #endregion

    #region Builder helpers

    private PadesSignerBuilder WithCredential(SigningCredential credential) =>
        With(_options with { Credential = credential });

    private PadesSignerBuilder With(PadesSigningOptions options) =>
        new(_inputPdf, options, _executionGate);

    private void EnterExecution()
    {
        if (_executionGate is not null && !_executionGate.TryEnter())
        {
            throw new SigningException(
                "A builder created from a stream may execute only once. Create a new builder for another signing operation.",
                SigningErrorReason.DocumentNotSignable);
        }
    }

    private sealed class PadesExecutionGate
    {
        private int _entered;

        public bool TryEnter() => Interlocked.Exchange(ref _entered, 1) == 0;
    }

    private static IReadOnlyList<X509Certificate2> CopyChain(IReadOnlyList<X509Certificate2> chain) =>
        chain.ToList().AsReadOnly();

    private static SignatureMetadata CopyMetadata(SignatureMetadata source) => new()
    {
        SignerName = source.SignerName,
        SignerId = source.SignerId,
        SignerIdType = source.SignerIdType,
        Email = source.Email,
        IpAddress = source.IpAddress,
        AuthenticationMethod = source.AuthenticationMethod,
        InstitutionName = source.InstitutionName,
        InstitutionId = source.InstitutionId,
        InstitutionIdType = source.InstitutionIdType,
        CommitmentType = source.CommitmentType,
        LegalBasis = source.LegalBasis,
        PolicyOid = source.PolicyOid,
        PolicyUri = source.PolicyUri,
        Reason = source.Reason,
        ContactInfo = source.ContactInfo,
        Location = source.Location,
        ExtraAttributes = source.ExtraAttributes?.ToArray()
    };

    private static SignatureFieldOptions SnapshotField(SignatureFieldOptions source) => source.Snapshot();

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

/// <summary>Hands a prepared timestamp client (with its credentials) to code that takes a factory.</summary>
internal sealed class FixedTimestampClientFactory(ITimestampClient client) : ITimestampClientFactory
{
    public ITimestampClient Create(string tsaUrl) => client;
}
