using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES.Internal;

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
            SignaturePolicy: null,
            SigningCertificateForm: XadesSigningCertificateForm.V2,
            ExtendedForm: XadesExtendedForm.None,
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
            SignaturePolicy: null,
            SigningCertificateForm: XadesSigningCertificateForm.V2,
            ExtendedForm: XadesExtendedForm.None,
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
        return With(_options with { SignaturePolicy = new SignaturePolicyReference(oid, null, ReadOnlyMemory<byte>.Empty, uri) });
    }

    /// <summary>
    /// Sets the signature policy with its hash: writes the OID as an OID URN and SigPolicyHash with
    /// <see cref="SignaturePolicyReference.Hash"/> (the digest the policy issuer publishes).
    /// </summary>
    /// <param name="policy">The policy reference (OID, hash algorithm, hash and optional URI).</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public XadesSignerBuilder WithSignaturePolicy(SignaturePolicyReference policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(policy.Oid, nameof(policy));
        return With(_options with { SignaturePolicy = policy });
    }

    /// <summary>
    /// Chooses the signing-certificate property: <see cref="XadesSigningCertificateForm.V2"/>
    /// (default) or the XAdES 1.3.2 <see cref="XadesSigningCertificateForm.V1"/> that the
    /// ICP-Brasil XML policies mandate.
    /// </summary>
    /// <param name="form">The form.</param>
    /// <returns>A new builder with the form configured.</returns>
    public XadesSignerBuilder WithSigningCertificateForm(XadesSigningCertificateForm form) =>
        With(_options with { SigningCertificateForm = form });

    /// <summary>
    /// Adds the XAdES extended forms of ETSI TS 101 903 v1.3.2 after the signature timestamp
    /// (requires a timestamped profile): CompleteCertificateRefs and CompleteRevocationRefs, a
    /// SigAndRefsTimeStamp (XAdES-X), CertificateValues/RevocationValues (XAdES-X-L) and an
    /// ArchiveTimeStamp (XAdES-A), as ICP-Brasil's AD-RV, AD-RC and AD-RA XML policies mandate.
    /// The CRL or OCSP response of every certificate in the path must be obtainable.
    /// </summary>
    /// <param name="form">The extended form.</param>
    /// <returns>A new builder with the form configured.</returns>
    public XadesSignerBuilder WithExtendedValidationData(XadesExtendedForm form) =>
        With(_options with { ExtendedForm = form });

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

    /// <summary>
    /// Signs one more data object together with the document: a file carried inside the signature
    /// (<see cref="XadesDataObject.Embedded"/>) or kept outside it (<see cref="XadesDataObject.External"/>).
    /// Each call adds a ds:Reference (W3C XMLDSig Core 1.1 §4.4.3); a data objects timestamp covers
    /// them too. Not available for a countersignature.
    /// </summary>
    /// <param name="dataObject">The data object.</param>
    /// <returns>A new builder with the data object added.</returns>
    /// <exception cref="ArgumentException">An external data object with the same URI was already added, or it uses the data URI of the detached form.</exception>
    public XadesSignerBuilder WithAdditionalDataObject(XadesDataObject dataObject)
    {
        ArgumentNullException.ThrowIfNull(dataObject);
        var current = _options.AdditionalDataObjects ?? [];
        if (dataObject.Uri is not null && current.Any(o => o.Uri == dataObject.Uri))
        {
            throw new ArgumentException($"An external data object with the URI '{dataObject.Uri}' was already added.", nameof(dataObject));
        }

        return With(_options with { AdditionalDataObjects = [.. current, dataObject] });
    }

    /// <summary>Configures the builder to countersign a signature of the document.</summary>
    internal XadesSignerBuilder ForCounterSignature(string? signatureId) =>
        With(_options with { IsCounterSignature = true, CounterSignTargetId = signatureId });

    /// <summary>
    /// Adds the AllDataObjectsTimeStamp signed property: a timestamp over the signed data, requested
    /// from <paramref name="timestamp"/> before signing, which proves the data existed before the
    /// signature (ETSI EN 319 132-1 §5.2.8.1). It is independent of the level: a B-B signature can
    /// carry it. Signing fails when the TSA does not answer.
    /// </summary>
    /// <param name="timestamp">The TSA that timestamps the data.</param>
    /// <returns>A new builder with the data objects timestamp configured.</returns>
    public XadesSignerBuilder WithDataObjectsTimestamp(TimestampOptions timestamp)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        return With(_options with { DataObjectsTimestamp = timestamp });
    }

    /// <summary>
    /// Chooses the XML canonicalization of SignedInfo and of the signed references
    /// (W3C XMLDSig Core 1.1 §4.4.1). Default: <see cref="XadesCanonicalization.Exclusive"/>.
    /// The time-stamps the library adds declare their own canonicalization and keep the exclusive one.
    /// </summary>
    /// <param name="canonicalization">The canonicalization algorithm.</param>
    /// <returns>A new builder with the canonicalization configured.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="canonicalization"/> is not a defined value.</exception>
    public XadesSignerBuilder WithCanonicalization(XadesCanonicalization canonicalization)
    {
        if (!Enum.IsDefined(canonicalization))
        {
            throw new ArgumentOutOfRangeException(nameof(canonicalization));
        }

        return With(_options with { Canonicalization = canonicalization });
    }

    /// <summary>
    /// Adds the SignaturePolicyStore unsigned property: the policy document itself, or the URI of
    /// a local store that holds it, so the policy can be read offline
    /// (ETSI EN 319 132-1 §5.2.10). Signing fails unless the signature also declares the policy
    /// with its hash (<see cref="WithSignaturePolicy(SignaturePolicyReference)"/>), which is what
    /// protects the stored document.
    /// </summary>
    /// <param name="store">The policy document or its local URI.</param>
    /// <returns>A new builder with the policy store configured.</returns>
    public XadesSignerBuilder WithSignaturePolicyStore(SignaturePolicyStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        return With(_options with { PolicyStore = store });
    }

    /// <summary>
    /// Adds the SignatureProductionPlaceV2 signed property: where the signer was when signing
    /// (ETSI EN 319 132-1 §5.2.5). With <see cref="XadesSigningCertificateForm.V1"/> it is written as
    /// the XAdES 1.3.2 SignatureProductionPlace, which has no street address.
    /// </summary>
    /// <param name="place">The place; at least one of its fields must be set.</param>
    /// <returns>A new builder with the production place configured.</returns>
    /// <exception cref="ArgumentException">Every field of <paramref name="place"/> is empty.</exception>
    public XadesSignerBuilder WithSignatureProductionPlace(SignatureProductionPlace place)
    {
        ArgumentNullException.ThrowIfNull(place);
        if (string.IsNullOrWhiteSpace(place.City) && string.IsNullOrWhiteSpace(place.StreetAddress)
            && string.IsNullOrWhiteSpace(place.StateOrProvince) && string.IsNullOrWhiteSpace(place.PostalCode)
            && string.IsNullOrWhiteSpace(place.CountryName))
        {
            throw new ArgumentException("The production place needs at least one field.", nameof(place));
        }

        return With(_options with { ProductionPlace = place });
    }

    /// <summary>
    /// Adds X.509 attribute certificates issued to the signer by an Attribute Authority, as
    /// certified roles of SignerRoleV2 (ETSI EN 319 132-1 §5.2.6, CertifiedRolesV2). The
    /// certificates are embedded as given: the library does not verify their signature, their
    /// holder or their validity. Not available with the XAdES 1.3.2 signing certificate form.
    /// </summary>
    /// <param name="attributeCertificates">The DER-encoded attribute certificates (IETF RFC 5755).</param>
    /// <returns>A new builder with the attribute certificates configured.</returns>
    /// <exception cref="ArgumentException">An item is not one DER-encoded SEQUENCE.</exception>
    public XadesSignerBuilder WithAttributeCertificates(IReadOnlyList<ReadOnlyMemory<byte>> attributeCertificates)
    {
        ArgumentNullException.ThrowIfNull(attributeCertificates);
        var copies = new List<ReadOnlyMemory<byte>>(attributeCertificates.Count);
        foreach (ReadOnlyMemory<byte> attributeCertificate in attributeCertificates)
        {
            try
            {
                var reader = new System.Formats.Asn1.AsnReader(attributeCertificate, System.Formats.Asn1.AsnEncodingRules.DER);
                _ = reader.ReadSequence();
                reader.ThrowIfNotEmpty();
            }
            catch (System.Formats.Asn1.AsnContentException ex)
            {
                throw new ArgumentException("An attribute certificate must be one DER-encoded SEQUENCE.", nameof(attributeCertificates), ex);
            }

            copies.Add(attributeCertificate.ToArray());
        }

        return With(_options with { AttributeCertificates = copies.AsReadOnly() });
    }

    /// <summary>
    /// Adds assertions about the signer signed by third parties, for example SAML assertions, as
    /// SignedAssertions of SignerRoleV2 (ETSI EN 319 132-1 §5.2.6). Each assertion is one XML
    /// element, embedded as given: the library does not verify the third party's signature.
    /// Not available with the XAdES 1.3.2 signing certificate form.
    /// </summary>
    /// <param name="assertions">The assertions, each as the text of one XML element.</param>
    /// <returns>A new builder with the signed assertions configured.</returns>
    /// <exception cref="ArgumentException">An assertion is not a well-formed XML element.</exception>
    public XadesSignerBuilder WithSignedAssertions(IReadOnlyList<string> assertions)
    {
        ArgumentNullException.ThrowIfNull(assertions);
        foreach (string assertion in assertions)
        {
            try
            {
                _ = XadesSignatureBuilder.ParseAssertion(assertion ?? string.Empty);
            }
            catch (System.Xml.XmlException ex)
            {
                throw new ArgumentException($"A signed assertion must be one well-formed XML element: {ex.Message}", nameof(assertions), ex);
            }
        }

        return With(_options with { SignedAssertions = assertions.ToList().AsReadOnly() });
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
    /// <exception cref="ArgumentException">The document is not well-formed XML or has no root element.</exception>
    public async Task<byte[]> SignAsync(CancellationToken cancellationToken = default)
    {
        BaselineSigning.EnsureStrictProfile(_options.Profile);
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
        if (_options.ExtendedForm != XadesExtendedForm.None && profile.Timestamp is null)
        {
            throw new SigningException(
                "WithExtendedValidationData needs a timestamped profile (AdesBaselineProfile.Timestamped).",
                SigningErrorReason.LevelNotAchievable);
        }

        if (_options.IsCounterSignature)
        {
            EnsureCounterSignatureOptions(profile);
        }

        if (_options.Form == XadesForm.Detached && _options.AdditionalDataObjects is { } additional
            && additional.Any(o => o.Uri == _options.DataUri))
        {
            throw new SigningException(
                $"An additional data object uses the URI '{_options.DataUri}', which is the data URI of the detached document.",
                SigningErrorReason.Unspecified);
        }

        if (_options.SigningCertificateForm == XadesSigningCertificateForm.V1
            && (_options.AttributeCertificates is { Count: > 0 } || _options.SignedAssertions is { Count: > 0 }))
        {
            throw new SigningException(
                "Attribute certificates and signed assertions go in SignerRoleV2, which the XAdES 1.3.2 form does not have: use the default signing certificate form.",
                SigningErrorReason.Unspecified);
        }

        if (_options.SigningCertificateForm == XadesSigningCertificateForm.V1
            && !string.IsNullOrWhiteSpace(_options.ProductionPlace?.StreetAddress))
        {
            throw new SigningException(
                "The street address goes in SignatureProductionPlaceV2, which the XAdES 1.3.2 form does not have: leave it out or use the default signing certificate form.",
                SigningErrorReason.Unspecified);
        }

        if (_options.PolicyStore is not null && _options.SignaturePolicy is not { Hash.IsEmpty: false })
        {
            throw new SigningException(
                "A SignaturePolicyStore needs the signature policy declared with its hash: call WithSignaturePolicy(SignaturePolicyReference) (ETSI EN 319 132-1 §6.3).",
                SigningErrorReason.Unspecified);
        }

        var warnings = new List<SigningWarning>();
        var resolvedAlgorithm = SigningAlgorithmResolver.Resolve(
            certificate, _options.HashAlgorithm, _options.HashAlgorithmExplicitlySet, _options.SignatureAlgorithmOid);
        var hashAlg = resolvedAlgorithm.HashAlgorithm;
        string sigAlgOid = resolvedAlgorithm.SignatureAlgorithmOid;

        var logger = _options.Dependencies.Logger;
        string operationId = _options.OperationId ?? "-";
        var stopwatch = Stopwatch.StartNew();
        logger.SigningStarted(operationId, _options.Form.ToString(), profile.Level.ToString(),
            _options.ExtendedForm.ToString(), certificate.Subject, credential is XadesExternalCredential);
        logger.AlgorithmResolved(hashAlg.Name ?? "?", sigAlgOid);

        // The Ids of the additional data objects are chosen once: with an external key the signature is assembled twice.
        var additionalReferences = XadesSignatureBuilder.PlanAdditionalReferences(_options.AdditionalDataObjects);
        var detachedData = DetachedData();

        byte[] signedXml;
        string targetSignatureId;
        if (_options.IsCounterSignature)
        {
            (signedXml, targetSignatureId) = await CounterSignCoreAsync(
                credential, certificate, chain, hashAlg, sigAlgOid, resolvedAlgorithm.RsaPssParameters, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            // The data objects timestamp is a signed property, so the TSA is asked before the signature is made.
            XadesDataObjectsTimeStamp? dataObjectsTimeStamp = _options.DataObjectsTimestamp is { } dataTsa
                ? await RequestDataObjectsTimeStampAsync(dataTsa, hashAlg, operationId, additionalReferences, cancellationToken).ConfigureAwait(false)
                : null;

            signedXml = credential is XadesExternalCredential external
                ? await SignExternalCoreAsync(external, certificate, chain, hashAlg, sigAlgOid, resolvedAlgorithm.RsaPssParameters, dataObjectsTimeStamp, additionalReferences, cancellationToken).ConfigureAwait(false)
                : SignLocalCore(certificate, chain, hashAlg, sigAlgOid, dataObjectsTimeStamp, additionalReferences);
            targetSignatureId = XadesSignatureBuilder.GetLastSignatureId(signedXml);
        }

        // The policy store goes in before the timestamps, so an archive timestamp covers it.
        if (_options.PolicyStore is { } policyStore)
        {
            signedXml = XadesSignatureBuilder.EmbedSignaturePolicyStore(signedXml, policyStore, targetSignatureId);
        }

        byte[]? timestampTokenBytes = null;
        if (profile.Timestamp is not null)
        {
            try
            {
                logger.TimestampRequested(operationId, profile.Timestamp.Endpoint.ToString());
                timestampTokenBytes = await ApplyTimestampAsync(signedXml, targetSignatureId, hashAlg, profile.Timestamp, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.TimestampFailed(operationId, ex.Message);
                if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
                {
                    throw new SigningException(
                        $"Signature timestamp request failed: {ex.Message}",
                        SigningErrorReason.NetworkFailure,
                        ex);
                }

                BaselineSigning.AddDowngradeWarnings(warnings, SigningWarningCode.SignatureTimestampUnavailable,
                    $"Signature timestamp could not be applied: {ex.Message}");
            }

            if (timestampTokenBytes is not null)
            {
                signedXml = XadesSignatureBuilder.EmbedSignatureTimeStamp(signedXml, timestampTokenBytes, targetSignatureId);
                logger.TimestampEmbedded(operationId, timestampTokenBytes.Length);
            }
        }

        XadesLtvEmbeddingResult? ltvEmbedding = null;
        bool hasArchiveTimestamp = false;
        if (_options.ExtendedForm != XadesExtendedForm.None)
        {
            if (timestampTokenBytes is null)
            {
                throw new SigningException(
                    "The XAdES extended forms need the signature timestamp, which could not be obtained.",
                    SigningErrorReason.LevelNotAchievable);
            }

            (signedXml, ltvEmbedding) = await ApplyExtendedFormAsync(
                signedXml, targetSignatureId, certificate, chain, hashAlg, profile.Timestamp!, cancellationToken).ConfigureAwait(false);
            if (_options.ExtendedForm == XadesExtendedForm.Archive)
            {
                signedXml = await ApplyArchiveTimestampAsync(signedXml, targetSignatureId, hashAlg, cancellationToken).ConfigureAwait(false);
                hasArchiveTimestamp = true;
            }
        }
        else if (timestampTokenBytes is not null && profile.Level >= AdesBaselineLevel.LongTerm)
        {
            ltvEmbedding = await ApplyLtvAsync(signedXml, targetSignatureId, certificate, chain, cancellationToken).ConfigureAwait(false);
            if (ltvEmbedding is not null)
            {
                signedXml = ltvEmbedding.SignedXml;
            }
            else
            {
                logger.LtvIncomplete(operationId);
                BaselineSigning.AddDowngradeWarnings(warnings, SigningWarningCode.LongTermValidationMaterialUnavailable,
                    "LTV was requested but no certificate and revocation data could be collected.");
            }
        }

        if (_options.ExtendedForm == XadesExtendedForm.None && ltvEmbedding is not null && profile.Level >= AdesBaselineLevel.Archive)
        {
            try
            {
                signedXml = await ApplyArchiveTimestampAsync(signedXml, targetSignatureId, hashAlg, cancellationToken).ConfigureAwait(false);
                hasArchiveTimestamp = true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                const string archiveMessage = "XAdES ArchiveTimeStamp could not be applied.";
                logger.ArchiveTimestampFailed(operationId, ex.Message);
                if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
                {
                    throw new SigningException(archiveMessage, SigningErrorReason.LevelNotAchievable, ex);
                }

                BaselineSigning.AddDowngradeWarnings(warnings, SigningWarningCode.ArchiveTimestampUnavailable,
                    $"{archiveMessage} {ex.Message}");
            }
        }

        // A countersignature is validated under the signature it signs, and signs no document data.
        XadesValidationResult? validatedSignature = FindSignature(
            new XadesSignatureValidator().ValidateAll(signedXml, trustAnchors: null, _options.IsCounterSignature ? null : detachedData),
            targetSignatureId);
        logger.ReadBackVerified(targetSignatureId, validatedSignature?.IsSignatureValid ?? false,
            validatedSignature?.IsIntegrityValid ?? false);
        if (validatedSignature is null || !validatedSignature.IsSignatureValid ||
            !validatedSignature.IsIntegrityValid)
        {
            throw new SigningException(
                "The completed XML signature or signed content failed read-back verification.",
                SigningErrorReason.Unspecified);
        }

        string? signatureId = validatedSignature.SignatureId;
        bool artifactHasTimestamp = timestampTokenBytes is not null &&
            validatedSignature.HasValidSignatureTimeStamp == true &&
            XadesSignatureBuilder.ExtractSignatureTimeStamp(signedXml, signatureId) is byte[] embeddedTimestamp &&
            CryptographicOperations.FixedTimeEquals(embeddedTimestamp, timestampTokenBytes);
        bool artifactHasLtvMaterial = artifactHasTimestamp && ltvEmbedding is not null &&
            validatedSignature.IsLtvDataValid == true &&
            XadesSignatureBuilder.HasLtvData(signedXml, ltvEmbedding.Evidence);
        bool artifactHasArchiveTimestamp = artifactHasLtvMaterial && hasArchiveTimestamp &&
            validatedSignature.HasValidArchiveTimeStamp == true &&
            XadesSignatureBuilder.ValidateArchiveTimeStamp(signedXml, detachedData, [], signatureId);
        if (timestampTokenBytes is not null && !artifactHasTimestamp)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.SignatureTimestampUnavailable,
                "The produced XML does not contain the requested signature timestamp token.");
        }

        if (ltvEmbedding is not null && !artifactHasLtvMaterial)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.LongTermValidationMaterialUnavailable,
                "The produced XML does not contain complete LTV properties.");
        }

        if (hasArchiveTimestamp && !artifactHasArchiveTimestamp)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.ArchiveTimestampUnavailable,
                "The produced XML does not contain an ArchiveTimeStamp covering its ETSI-defined input.");
        }

        var achieved = BaselineSigning.AchievedLevel(artifactHasTimestamp, artifactHasLtvMaterial, artifactHasArchiveTimestamp);
        logger.SigningCompleted(operationId, stopwatch.ElapsedMilliseconds, signedXml.Length,
            profile.Level.ToString(), achieved.ToString());

        return new XadesSigningResult
        {
            SignedArtifact = signedXml,
            RequestedLevel = profile.Level,
            AchievedLevel = achieved,
            HasSignatureTimestamp = artifactHasTimestamp,
            HasLongTermValidationMaterial = artifactHasLtvMaterial,
            HasArchiveTimestamp = artifactHasArchiveTimestamp,
            Warnings = warnings.AsReadOnly()
        };
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

        BaselineSigning.EnsureCertificateValidNow(certificate);
    }

    private static X509Certificate2 GetCertificate(XadesSigningCredential credential) => credential switch
    {
        XadesLocalCredential c => c.Certificate,
        XadesExternalCredential c => c.Certificate,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    /// <summary>The signer certificate given to WithCertificate or WithExternalSigner, or <see langword="null"/> before either is called. Extensions read it to pick policies.</summary>
    public X509Certificate2? SignerCertificate => _options.Credential is { } credential ? GetCertificate(credential) : null;

    /// <summary>The certificate chain given with the signer certificate (empty when none was given).</summary>
    public IReadOnlyList<X509Certificate2> SignerChain => _options.Credential is { } credential ? GetChain(credential) : [];

    private static IReadOnlyList<X509Certificate2> GetChain(XadesSigningCredential credential) => credential switch
    {
        XadesLocalCredential c => c.Chain,
        XadesExternalCredential c => c.Chain,
        _ => throw new InvalidOperationException($"Unknown signing credential type: {credential.GetType().Name}")
    };

    private byte[] SignLocalCore(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        HashAlgorithmName hashAlg,
        string sigAlgOid,
        XadesDataObjectsTimeStamp? dataObjectsTimeStamp,
        IReadOnlyList<XadesAdditionalReference>? additionalReferences)
    {
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;
        return XadesSignatureBuilder.BuildSignature(
            _xmlData, certificate, hashAlg, signingTime, chain,
            _options.CommitmentType, _options.SignaturePolicy, _options.SigningCertificateForm,
            sigAlgOid, _options.Form, _options.Roles, _options.DataObjectFormat, _options.ProductionPlace, dataObjectsTimeStamp, additionalReferences,
            _options.Dependencies.Logger, _options.DataUri,
            XadesSignatureBuilder.CanonicalizationUri(_options.Canonicalization));
    }

    private async Task<byte[]> SignExternalCoreAsync(
        XadesExternalCredential external,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        HashAlgorithmName hashAlg,
        string sigAlgOid,
        RsaPssParameters? rsaPssParameters,
        XadesDataObjectsTimeStamp? dataObjectsTimeStamp,
        IReadOnlyList<XadesAdditionalReference>? additionalReferences,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;

        byte[] signedInfoBytes = XadesSignatureBuilder.BuildSignedInfoToHash(
            _xmlData, certificate, hashAlg, signingTime, _options.Form,
            _options.CommitmentType, _options.SignaturePolicy, _options.SigningCertificateForm,
            sigAlgOid, _options.Roles, _options.DataObjectFormat, _options.ProductionPlace, dataObjectsTimeStamp, additionalReferences,
            out string signedPropertiesId,
            out byte[] signedInfoXml,
            out string? dataObjectId, _options.DataUri,
            XadesSignatureBuilder.CanonicalizationUri(_options.Canonicalization));

        var request = new ExternalSigningRequest(
            signedInfoBytes,
            hashAlg,
            sigAlgOid,
            ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo,
            _options.OperationId,
            rsaPssParameters);
        _options.Dependencies.Logger.ExternalSignerInvoked(signedInfoBytes.Length);
        ReadOnlyMemory<byte> signature = await BaselineSigning
            .SignExternallyAsync(external.Signer, request, certificate, cancellationToken).ConfigureAwait(false);
        _options.Dependencies.Logger.ExternalSignatureReceived(signature.Length);

        return XadesSignatureBuilder.CompleteWithExternalSignature(
            _xmlData, certificate, hashAlg, signingTime, chain,
            _options.CommitmentType, _options.SignaturePolicy, _options.SigningCertificateForm,
            sigAlgOid, signedInfoXml, signature.ToArray(), signedPropertiesId,
            _options.Roles, _options.DataObjectFormat, _options.ProductionPlace, dataObjectsTimeStamp, additionalReferences, _options.Form, _options.DataUri, dataObjectId);
    }

    /// <summary>
    /// The data the signature references outside the document: the document itself for the detached
    /// form, and each external additional data object by its URI.
    /// </summary>
    private XadesDetachedData DetachedData()
    {
        var byUri = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (XadesDataObject dataObject in _options.AdditionalDataObjects ?? [])
        {
            if (dataObject.Uri is not null)
            {
                byUri[dataObject.Uri] = dataObject.Content.ToArray();
            }
        }

        return new XadesDetachedData(_xmlData, byUri);
    }

    /// <summary>The last result with the given signature Id, searching countersignatures too.</summary>
    private static XadesValidationResult? FindSignature(IEnumerable<XadesValidationResult> results, string signatureId)
    {
        XadesValidationResult? found = null;
        foreach (var result in results)
        {
            if (result.SignatureId == signatureId)
            {
                found = result;
            }

            found = FindSignature(result.CounterSignatures, signatureId) ?? found;
        }

        return found;
    }

    /// <summary>Refuses what a countersignature cannot carry or what this builder does not build for one.</summary>
    private void EnsureCounterSignatureOptions(AdesBaselineProfile profile)
    {
        string? unsupported =
            profile.Level > AdesBaselineLevel.Timestamped ? "a level above B-T"
            : _options.ExtendedForm != XadesExtendedForm.None ? "an extended form"
            : _options.DataObjectsTimestamp is not null ? "a data objects timestamp (it signs a signature value, not data)"
            : _options.DataObjectFormat is not null ? "a data object format (it signs a signature value, not data)"
            : _options.AdditionalDataObjects is { Count: > 0 } ? "additional data objects (it signs a signature value, not data)"
            : null;
        if (unsupported is not null)
        {
            throw new SigningException($"A countersignature cannot be built with {unsupported}.", SigningErrorReason.LevelNotAchievable);
        }
    }

    /// <summary>Builds the countersignature in the document and signs its SignedInfo with the local or the external key.</summary>
    private async Task<(byte[] SignedXml, string SignatureId)> CounterSignCoreAsync(
        XadesSigningCredential credential,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        HashAlgorithmName hashAlg,
        string sigAlgOid,
        RsaPssParameters? rsaPssParameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var preparation = XadesSignatureBuilder.PrepareCounterSignature(
            _xmlData, _options.CounterSignTargetId, certificate, hashAlg, _options.SigningTime ?? DateTimeOffset.UtcNow, chain,
            _options.CommitmentType, _options.SignaturePolicy, _options.SigningCertificateForm, sigAlgOid,
            _options.Roles, _options.ProductionPlace, XadesSignatureBuilder.CanonicalizationUri(_options.Canonicalization));

        byte[] signatureValue;
        if (credential is XadesExternalCredential external)
        {
            var request = new ExternalSigningRequest(
                preparation.SignedInfoCanonical,
                hashAlg,
                sigAlgOid,
                ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo,
                _options.OperationId,
                rsaPssParameters);
            _options.Dependencies.Logger.ExternalSignerInvoked(preparation.SignedInfoCanonical.Length);
            ReadOnlyMemory<byte> signature = await BaselineSigning
                .SignExternallyAsync(external.Signer, request, certificate, cancellationToken).ConfigureAwait(false);
            _options.Dependencies.Logger.ExternalSignatureReceived(signature.Length);
            signatureValue = signature.ToArray();
        }
        else
        {
            signatureValue = XadesSignatureBuilder.SignCanonicalSignedInfo(preparation.SignedInfoCanonical, hashAlg, sigAlgOid, certificate);
        }

        return (XadesSignatureBuilder.CompleteCounterSignature(preparation.PreparedXml, preparation.SignatureId, signatureValue), preparation.SignatureId);
    }

    /// <summary>Asks the TSA for a timestamp over the octets the data reference will digest.</summary>
    private async Task<XadesDataObjectsTimeStamp> RequestDataObjectsTimeStampAsync(
        TimestampOptions timestamp, HashAlgorithmName hashAlg, string operationId,
        IReadOnlyList<XadesAdditionalReference>? additionalReferences, CancellationToken cancellationToken)
    {
        var logger = _options.Dependencies.Logger;
        string? dataObjectId = _options.Form == XadesForm.Enveloping ? XadesSignatureBuilder.NewDataObjectId() : null;
        byte[] input = XadesSignatureBuilder.DataObjectsTimeStampInput(
            _xmlData, _options.Form, XadesSignatureBuilder.CanonicalizationUri(_options.Canonicalization), dataObjectId, additionalReferences);
        try
        {
            logger.TimestampRequested(operationId, timestamp.Endpoint.ToString());
            byte[] token = await CreateTimestampClient(timestamp).GetTimestampAsync(input, hashAlg, cancellationToken).ConfigureAwait(false);
            TimestampClient.ValidateTimestampToken(token, input, hashAlg);
            return new XadesDataObjectsTimeStamp(token, dataObjectId);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.TimestampFailed(operationId, ex.Message);
            throw new SigningException($"Data objects timestamp request failed: {ex.Message}", SigningErrorReason.NetworkFailure, ex);
        }
    }

    private async Task<byte[]?> ApplyTimestampAsync(
        byte[] signedXml,
        string signatureId,
        HashAlgorithmName hashAlg,
        TimestampOptions timestampOptions,
        CancellationToken cancellationToken)
    {
        var tsaClient = CreateTimestampClient(timestampOptions);
        byte[] timestampInput = XadesSignatureBuilder.CreateSignatureTimeStampInput(signedXml, signatureId);
        byte[] tsToken = await tsaClient.GetTimestampAsync(timestampInput, hashAlg, cancellationToken).ConfigureAwait(false);
        TimestampClient.ValidateTimestampToken(tsToken, timestampInput, hashAlg);

        return tsToken;
    }

    private ITimestampClient CreateTimestampClient(TimestampOptions timestampOptions) =>
        BaselineSigning.CreateTimestampClient(
            timestampOptions, _options.Dependencies.TsaFactory, _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger);

    private ITimestampClient CreateTimestampClient(string endpoint, IHttpClientProvider? scopedProvider) =>
        BaselineSigning.CreateTimestampClient(
            endpoint, scopedProvider, _options.Dependencies.TsaFactory, _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger);

    private async Task<(byte[] SignedXml, XadesLtvEmbeddingResult? Ltv)> ApplyExtendedFormAsync(
        byte[] signedXml,
        string signatureId,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        HashAlgorithmName hashAlg,
        TimestampOptions timestamp,
        CancellationToken cancellationToken)
    {
        var known = new List<X509Certificate2> { certificate };
        known.AddRange(chain.Where(c => known.All(k => k.Thumbprint != c.Thumbprint)));
        if (XadesSignatureBuilder.ExtractSignatureTimeStamp(signedXml, signatureId) is { } signatureTimestamp)
        {
            known.AddRange(TsaCertificateExtractor.ExtractCertificates(signatureTimestamp).Where(c => known.All(k => k.Thumbprint != c.Thumbprint)));
        }

        var logger = _options.Dependencies.Logger;
        string operationId = _options.OperationId ?? "-";
        logger.ExtendedFormApplying(operationId, _options.ExtendedForm.ToString());
        logger.LtvCollecting(operationId, known.Count);
        var provider = _options.Profile.LongTermValidation?.HttpClientProvider ?? timestamp.HttpClientProvider ?? _options.Dependencies.HttpClientProvider;
        var ltvOptions = _options.Profile.LongTermValidation ?? new LongTermValidationOptions();
        var evidence = await LtvEvidenceCollector.CollectAsync(
            provider.GetClient(), certificate, known, logger,
            revocationPreference: ltvOptions.RevocationPreference,
            outboundPolicy: provider.OutboundPolicy ?? OutboundHttpPolicy.Default,
            clockSkewTolerance: ltvOptions.ClockSkewTolerance,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!evidence.HasCompleteCoverage)
        {
            throw new SigningException(
                "The XAdES extended forms need the CRL or OCSP response of every certificate in the path; some could not be collected.",
                SigningErrorReason.LevelNotAchievable);
        }

        var path = RevocationEvidence.BuildPath(certificate, [.. evidence.CertificateRawData, .. known.Select(k => k.RawData)]);
        signedXml = XadesSignatureBuilder.EmbedCompleteReferences(signedXml, path, evidence.Crls, evidence.OcspResponses, signatureId);
        if (_options.ExtendedForm is XadesExtendedForm.CompleteReferences or XadesExtendedForm.ExtendedLong)
        {
            byte[] input = XadesSignatureBuilder.CreateSigAndRefsTimeStampInput(signedXml, signatureId);
            byte[] token = await CreateTimestampClient(timestamp).GetTimestampAsync(input, hashAlg, cancellationToken).ConfigureAwait(false);
            TimestampClient.ValidateTimestampToken(token, input, hashAlg);
            signedXml = XadesSignatureBuilder.EmbedSigAndRefsTimeStamp(signedXml, token, signatureId);
            logger.SigAndRefsTimestampEmbedded(operationId, token.Length);
        }

        if (_options.ExtendedForm is XadesExtendedForm.ExtendedLong or XadesExtendedForm.Archive)
        {
            signedXml = XadesSignatureBuilder.EmbedLtvData(signedXml, evidence, signatureId);
            logger.LtvEmbedded(operationId, evidence.CertificateRawData.Count, evidence.Crls.Count, evidence.OcspResponses.Count);
            return (signedXml, new XadesLtvEmbeddingResult(signedXml, evidence));
        }

        return (signedXml, null);
    }

    private async Task<XadesLtvEmbeddingResult?> ApplyLtvAsync(
        byte[] signedXml,
        string signatureId,
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

        byte[]? timestampToken = XadesSignatureBuilder.ExtractSignatureTimeStamp(signedXml, signatureId);
        if (timestampToken is not null)
        {
            foreach (var tsaCertificate in TsaCertificateExtractor.ExtractCertificates(timestampToken))
            {
                if (!chainCerts.Any(x => x.Thumbprint == tsaCertificate.Thumbprint))
                {
                    chainCerts.Add(tsaCertificate);
                }
            }
        }

        string operationId = _options.OperationId ?? "-";
        logger.LtvCollecting(operationId, chainCerts.Count);
        var ltvData = await LtvEvidenceCollector.CollectAsync(
            ltvProvider.GetClient(), certificate, chainCerts, logger,
            revocationPreference: profile.LongTermValidation.RevocationPreference,
            outboundPolicy: ltvProvider.OutboundPolicy ?? OutboundHttpPolicy.Default,
            clockSkewTolerance: profile.LongTermValidation.ClockSkewTolerance,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        bool hasLtvMaterial = ltvData.CertificateRawData.Count > 0 && ltvData.HasCompleteCoverage;
        if (!hasLtvMaterial)
        {
            if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
            {
                string missingEvidence = string.Join("; ",
                    (ltvData.CertificateEvidence ?? [])
                        .Where(item => !item.IsComplete)
                        .Select(item => $"{item.Thumbprint}: {item.AbsenceReason}"));
                throw new SigningException(
                    "LTV was requested but no certificate and revocation data could be collected. " +
                    "The requested B-LT/B-LTA level cannot be produced." +
                    (missingEvidence.Length > 0 ? $" Missing evidence: {missingEvidence}" : string.Empty),
                    SigningErrorReason.LevelNotAchievable);
            }

            return null;
        }

        logger.LtvEmbedded(operationId, ltvData.CertificateRawData.Count, ltvData.Crls.Count, ltvData.OcspResponses.Count);
        return new XadesLtvEmbeddingResult(XadesSignatureBuilder.EmbedLtvData(signedXml, ltvData, signatureId), ltvData);
    }

    private async Task<byte[]> ApplyArchiveTimestampAsync(
        byte[] signedXml,
        string signatureId,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken)
    {
        var profile = _options.Profile;
        var archiveOptions = profile.ArchiveTimestamp;
        var timestampOptions = profile.Timestamp!;
        var endpoint = archiveOptions?.Endpoint ?? timestampOptions.Endpoint;
        var scopedProvider = archiveOptions?.HttpClientProvider ?? timestampOptions.HttpClientProvider;

        byte[] withPlaceholder = XadesSignatureBuilder.EmbedArchiveTimeStamp(signedXml, [], signatureId);
        byte[] input = XadesSignatureBuilder.CreateArchiveTimeStampInput(withPlaceholder, DetachedData(), signatureId);
        var tsaClient = CreateTimestampClient(endpoint.ToString(), scopedProvider);
        string operationId = _options.OperationId ?? "-";
        _options.Dependencies.Logger.ArchiveTimestampRequested(operationId, endpoint.ToString());
        byte[] archiveToken = await tsaClient.GetTimestampAsync(input, hashAlgorithm, cancellationToken).ConfigureAwait(false);
        TimestampClient.ValidateTimestampToken(archiveToken, input, hashAlgorithm);

        byte[] completedXml = XadesSignatureBuilder.EmbedArchiveTimeStamp(signedXml, archiveToken, signatureId);
        var warnings = new List<string>();
        if (!XadesSignatureBuilder.ValidateArchiveTimeStamp(completedXml, DetachedData(), warnings, signatureId))
        {
            throw new SigningException(
                $"The produced ArchiveTimeStamp did not validate: {string.Join(" ", warnings)}",
                SigningErrorReason.LevelNotAchievable);
        }

        _options.Dependencies.Logger.ArchiveTimestampEmbedded(operationId, archiveToken.Length);
        return completedXml;
    }

    private XadesSignerBuilder WithCredential(XadesSigningCredential credential) =>
        With(_options with { Credential = credential });

    private sealed record XadesLtvEmbeddingResult(byte[] SignedXml, LtvEvidence Evidence);

    private XadesSignerBuilder With(XadesSigningOptions options) =>
        new(_xmlData, options);

    private static IReadOnlyList<X509Certificate2> CopyChain(IReadOnlyList<X509Certificate2> chain) =>
        chain.ToList().AsReadOnly();
}
