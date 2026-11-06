using System.Formats.Asn1;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.CAdES.Internal;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
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
    /// Sets the checks run before signing: validity of the chain, key usage, key size, hash algorithm
    /// and, with <see cref="SigningPolicy.Strict"/>, the revocation of the chain. Default: <see cref="SigningPolicy.Default"/>.
    /// </summary>
    /// <param name="policy">The signing policy.</param>
    /// <returns>A new builder with the policy configured.</returns>
    public CadesSignerBuilder WithSigningPolicy(SigningPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return With(_options with { SigningPolicy = policy });
    }

    /// <summary>Sets the checker used for the revocation check of <see cref="SigningPolicy.CheckRevocation"/>.</summary>
    /// <param name="checker">The chain revocation checker.</param>
    /// <returns>A new builder with the checker configured.</returns>
    public CadesSignerBuilder WithChainRevocationChecker(SimpleSign.Core.Revocation.IChainRevocationChecker checker)
    {
        ArgumentNullException.ThrowIfNull(checker);
        return With(_options with { Dependencies = _options.Dependencies with { ChainRevocationChecker = checker } });
    }

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
        return With(_options with { SignaturePolicyOid = oid, SignaturePolicyUri = uri, SignaturePolicy = null });
    }

    /// <summary>
    /// Sets the signature policy with its hash (sigPolicyHash), as required by policies such as
    /// ICP-Brasil's AD-RB/AD-RT.
    /// </summary>
    /// <param name="policy">The policy OID, hash and optional URI.</param>
    /// <returns>A new builder with the signature policy configured.</returns>
    public CadesSignerBuilder WithSignaturePolicy(SignaturePolicyReference policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return With(_options with { SignaturePolicy = policy, SignaturePolicyOid = null, SignaturePolicyUri = null });
    }

    /// <summary>
    /// Adds the content-time-stamp signed attribute: a timestamp over the content, requested from
    /// <paramref name="timestamp"/> before signing, which proves the content existed before the
    /// signature (ETSI EN 319 122-1 §5.2.8). It is independent of the level: a B-B signature can
    /// carry it. Signing fails when the TSA does not answer. Not allowed in a countersignature,
    /// which has no content of its own.
    /// </summary>
    /// <param name="timestamp">The TSA that timestamps the content.</param>
    /// <returns>A new builder with the content timestamp configured.</returns>
    public CadesSignerBuilder WithContentTimestamp(TimestampOptions timestamp)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        return With(_options with { ContentTimestamp = timestamp });
    }

    /// <summary>
    /// Adds the signature-policy-store unsigned attribute: the policy document itself, or the URI
    /// of a local store that holds it, so the policy can be read offline
    /// (ETSI EN 319 122-1 §5.2.10). Signing fails unless the signature also declares the policy
    /// with its hash (<see cref="WithSignaturePolicy(SignaturePolicyReference)"/>), which is what
    /// protects the stored document.
    /// </summary>
    /// <param name="store">The policy document or its local URI.</param>
    /// <returns>A new builder with the policy store configured.</returns>
    public CadesSignerBuilder WithSignaturePolicyStore(SignaturePolicyStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        return With(_options with { PolicyStore = store });
    }

    /// <summary>
    /// Adds the signer-location attribute: an address associated with the signer at the place of
    /// signing (ETSI EN 319 122-1 §5.2.5).
    /// </summary>
    /// <param name="location">The location; at least one of its fields must be set, with at most six postal address lines.</param>
    /// <returns>A new builder with the signer location configured.</returns>
    /// <exception cref="ArgumentException">No field is set, or the postal address has more than six lines or an empty line.</exception>
    public CadesSignerBuilder WithSignerLocation(CadesSignerLocation location)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(location.PostalAddress, nameof(location));
        if (string.IsNullOrWhiteSpace(location.CountryName) && string.IsNullOrWhiteSpace(location.LocalityName)
            && location.PostalAddress.Count == 0)
        {
            throw new ArgumentException("The signer location needs a country, a locality or a postal address.", nameof(location));
        }

        if (location.PostalAddress.Count > 6 || location.PostalAddress.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("The postal address takes one to six non-empty lines.", nameof(location));
        }

        return With(_options with { SignerLocation = location with { PostalAddress = location.PostalAddress.ToList().AsReadOnly() } });
    }

    /// <summary>
    /// Adds the content-hints attribute, which describes the signed content
    /// (IETF RFC 2634 §2.9, ETSI EN 319 122-1 §5.2.4.1). Not allowed in a countersignature.
    /// </summary>
    /// <param name="hints">The content type and, optionally, its description.</param>
    /// <returns>A new builder with the content hints configured.</returns>
    /// <exception cref="ArgumentException">The content type OID is empty, or the description is an empty string.</exception>
    public CadesSignerBuilder WithContentHints(CadesContentHints hints)
    {
        ArgumentNullException.ThrowIfNull(hints);
        ArgumentException.ThrowIfNullOrWhiteSpace(hints.ContentTypeOid, nameof(hints));
        if (hints.Description is { Length: 0 })
        {
            throw new ArgumentException("The content description cannot be empty; leave it null to omit it.", nameof(hints));
        }

        return With(_options with { ContentHints = hints });
    }

    /// <summary>
    /// Adds the mime-type attribute: the MIME type of the signed data, written as IETF RFC 2045
    /// defines it, for example "application/pdf" (ETSI EN 319 122-1 §5.2.4.2).
    /// Not allowed in a countersignature.
    /// </summary>
    /// <param name="mimeType">The MIME type.</param>
    /// <returns>A new builder with the MIME type configured.</returns>
    public CadesSignerBuilder WithMimeType(string mimeType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mimeType);
        return With(_options with { MimeType = mimeType.Trim() });
    }

    /// <summary>
    /// Adds the roles the signer claims, in the signer-attributes-v2 attribute
    /// (ETSI EN 319 122-1 §5.2.6.1, claimedAttributes). Each role is written as an X.509 role
    /// attribute (id-at-role) holding the role as text. Empty roles are left out.
    /// </summary>
    /// <param name="roles">The claimed roles.</param>
    /// <returns>A new builder with the signer roles configured.</returns>
    public CadesSignerBuilder WithSignerRoles(IReadOnlyList<string> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        return With(_options with
        {
            SignerRoles = roles.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim()).ToList().AsReadOnly(),
        });
    }

    /// <summary>
    /// Adds X.509 attribute certificates issued to the signer by an Attribute Authority, in the
    /// signer-attributes-v2 attribute (ETSI EN 319 122-1 §5.2.6.1, certifiedAttributesV2). The
    /// certificates are embedded as given: the library does not verify their signature, their
    /// holder or their validity.
    /// </summary>
    /// <param name="attributeCertificates">The DER-encoded attribute certificates (IETF RFC 5755).</param>
    /// <returns>A new builder with the attribute certificates configured.</returns>
    /// <exception cref="ArgumentException">An item is not one DER-encoded SEQUENCE.</exception>
    public CadesSignerBuilder WithAttributeCertificates(IReadOnlyList<ReadOnlyMemory<byte>> attributeCertificates)
    {
        ArgumentNullException.ThrowIfNull(attributeCertificates);
        var copies = new List<ReadOnlyMemory<byte>>(attributeCertificates.Count);
        foreach (ReadOnlyMemory<byte> attributeCertificate in attributeCertificates)
        {
            try
            {
                var reader = new AsnReader(attributeCertificate, AsnEncodingRules.DER);
                _ = reader.ReadSequence();
                reader.ThrowIfNotEmpty();
            }
            catch (AsnContentException ex)
            {
                throw new ArgumentException("An attribute certificate must be one DER-encoded SEQUENCE.", nameof(attributeCertificates), ex);
            }

            copies.Add(attributeCertificate.ToArray());
        }

        return With(_options with { AttributeCertificates = copies.AsReadOnly() });
    }

    /// <summary>
    /// Adds assertions about the signer signed by third parties, in the signer-attributes-v2
    /// attribute (ETSI EN 319 122-1 §5.2.6.1, signedAssertions), for example
    /// <see cref="CadesSignedAssertion.Saml(ReadOnlySpan{byte})"/>. The assertions are embedded as
    /// given: the library does not verify the third party's signature.
    /// </summary>
    /// <param name="assertions">The signed assertions.</param>
    /// <returns>A new builder with the signed assertions configured.</returns>
    /// <exception cref="ArgumentException">An assertion has no OID.</exception>
    public CadesSignerBuilder WithSignedAssertions(IReadOnlyList<CadesSignedAssertion> assertions)
    {
        ArgumentNullException.ThrowIfNull(assertions);
        if (assertions.Any(a => a is null || string.IsNullOrWhiteSpace(a.Oid)))
        {
            throw new ArgumentException("Every signed assertion needs the OID of its kind.", nameof(assertions));
        }

        return With(_options with { SignedAssertions = assertions.ToList().AsReadOnly() });
    }

    /// <summary>Adds one role the signer claims (see <see cref="WithSignerRoles(IReadOnlyList{string})"/>).</summary>
    /// <param name="role">The claimed role.</param>
    /// <returns>A new builder with the signer role configured.</returns>
    public CadesSignerBuilder WithSignerRole(string role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        return WithSignerRoles([role]);
    }

    /// <summary>
    /// Adds RFC 5126 extended validation data after the signature timestamp: complete references
    /// and an escTimeStamp (CAdES-C/X), plus certificate and revocation values (X-L), or references,
    /// values and an archive-time-stamp v2 (CAdES-A) — the forms ICP-Brasil's AD-RV, AD-RC and AD-RA
    /// policies mandate. Requires a timestamped level: B-T, B-LT or B-LTA
    /// (<c>WithLevel(AdesBaselineProfile.Timestamped(tsa))</c> or above); the TSA also stamps the
    /// escTimeStamp / archive time-stamp. On B-LT and B-LTA the extended attributes are added after
    /// the LT certificate and revocation values, so an archive-time-stamp v2 covers them, and before
    /// the B-LTA archive-time-stamp-v3, which covers everything.
    /// </summary>
    /// <param name="form">The extended form.</param>
    /// <returns>A new builder with the extended form configured.</returns>
    public CadesSignerBuilder WithExtendedValidationData(CadesExtendedForm form) =>
        With(_options with { ExtendedForm = form });

    /// <summary>Configures the builder to add its signer to <paramref name="existingSignature"/>.</summary>
    internal CadesSignerBuilder ForCoSignature(byte[] existingSignature, bool attached) =>
        With(_options with
        {
            CoSignTarget = existingSignature,
            ContentType = attached ? CadesContentType.Enveloped : CadesContentType.Detached,
        });

    /// <summary>Configures the builder to countersign signer <paramref name="signerIndex"/> of <paramref name="existingSignature"/>.</summary>
    internal CadesSignerBuilder ForCounterSignature(byte[] existingSignature, int signerIndex) =>
        With(_options with
        {
            CounterSignTarget = existingSignature,
            CounterSignIndex = signerIndex,
            ContentType = CadesContentType.Detached,
        });

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
        BaselineSigning.EnsureStrictProfile(_options.Profile);
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
        await SignerAcceptance.EnsureSignerAcceptableAsync(
            certificate, chain, _options.SigningPolicy, _options.Dependencies.ChainRevocationChecker,
            _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger, cancellationToken).ConfigureAwait(false);
        if (_options.IsCounterSignature && (_options.ContentHints is not null || _options.MimeType is not null))
        {
            throw new SigningException(
                "A countersignature cannot carry the content-hints or mime-type attributes (ETSI EN 319 122-1 §5.2.4).",
                SigningErrorReason.Unspecified);
        }

        if (_options.PolicyStore is not null && _options.SignaturePolicy is not { Hash.IsEmpty: false })
        {
            throw new SigningException(
                "A signature-policy-store needs the signature policy declared with its hash: call WithSignaturePolicy(SignaturePolicyReference) (ETSI EN 319 122-1 §6.3).",
                SigningErrorReason.Unspecified);
        }

        var warnings = new List<SigningWarning>();
        if (_options.HashAlgorithmExplicitlySet)
        {
            SignerAcceptance.EnsureHashAllowed(_options.HashAlgorithm, _options.SigningPolicy);
        }

        var resolvedAlgorithm = SigningAlgorithmResolver.Resolve(
            certificate, _options.HashAlgorithm, _options.HashAlgorithmExplicitlySet, _options.SignatureAlgorithmOid);
        var hashAlg = resolvedAlgorithm.HashAlgorithm;
        SignerAcceptance.EnsureHashAllowed(hashAlg, _options.SigningPolicy);
        string sigAlgOid = resolvedAlgorithm.SignatureAlgorithmOid;

        var logger = _options.Dependencies.Logger;
        string operationId = _options.OperationId ?? "-";
        var stopwatch = Stopwatch.StartNew();
        string operation = _options.IsCounterSignature ? "CounterSign" : _options.CoSignTarget is not null ? "CoSign" : "Sign";
        logger.SigningStarted(operationId, operation, _options.ContentType.ToString(), profile.Level.ToString(),
            _options.ExtendedForm.ToString(), certificate.Subject, credential is CadesExternalCredential);
        logger.AlgorithmResolved(hashAlg.Name ?? "?", sigAlgOid);
        logger.SignedAttributesSelected(_options.CommitmentType.HasValue,
            _options.SignaturePolicy is not null || _options.SignaturePolicyOid is not null);

        // The content timestamp is a signed attribute, so the TSA is asked before the signature is made.
        CmsAttribute? contentTimestamp = null;
        if (_options.ContentTimestamp is { } contentTsa)
        {
            if (_options.IsCounterSignature)
            {
                throw new SigningException(
                    "A countersignature cannot carry a content-time-stamp: it signs a signature value, not content (ETSI EN 319 122-1 §5.2.8).",
                    SigningErrorReason.Unspecified);
            }

            contentTimestamp = await RequestContentTimestampAsync(contentTsa, hashAlg, operationId, cancellationToken).ConfigureAwait(false);
        }

        byte[] cms;
        if (credential is CadesExternalCredential external)
        {
            cms = await SignExternalCoreAsync(external, certificate, chain, hashAlg, sigAlgOid, resolvedAlgorithm.RsaPssParameters, contentTimestamp, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            cms = SignLocalCore(certificate, chain, hashAlg, sigAlgOid, contentTimestamp);
        }

        // The policy store goes in before the timestamps, so an archive timestamp covers it.
        if (_options.PolicyStore is { } policyStore)
        {
            cms = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CadesSignaturePolicyStore.Encode(policyStore)]);
        }

        byte[]? timestampTokenBytes = null;
        if (profile.Timestamp is not null)
        {
            try
            {
                logger.TimestampRequested(operationId, profile.Timestamp.Endpoint.ToString());
                timestampTokenBytes = await ApplyTimestampAsync(cms, hashAlg, profile.Timestamp, cancellationToken).ConfigureAwait(false);
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
                cms = TimestampClient.EmbedTimestampInCms(cms, timestampTokenBytes);
                logger.TimestampEmbedded(operationId, timestampTokenBytes.Length);
            }
        }

        CadesLtvEmbeddingResult? ltvEmbedding = null;
        if (timestampTokenBytes is not null && profile.Level >= AdesBaselineLevel.LongTerm)
        {
            ltvEmbedding = await ApplyLtvAsync(cms, certificate, chain, cancellationToken).ConfigureAwait(false);
            if (ltvEmbedding is not null)
            {
                cms = ltvEmbedding.SignedCms;
            }
            else
            {
                logger.LtvIncomplete(operationId);
                BaselineSigning.AddDowngradeWarnings(warnings, SigningWarningCode.LongTermValidationMaterialUnavailable,
                    "LTV was requested but no certificate and revocation data could be collected.");
            }
        }

        // The extended form goes after the B-LT material and before the B-LTA archive-time-stamp-v3:
        // an archive-time-stamp v2 must cover the certificate and revocation values the LT step
        // adds, and the v3 timestamp must cover everything, the extended attributes included.
        if (_options.ExtendedForm != CadesExtendedForm.None)
        {
            if (profile.Timestamp is null || timestampTokenBytes is null)
            {
                throw new SigningException(
                    "Extended validation data needs a signature timestamp: use WithLevel(AdesBaselineProfile.Timestamped(tsa)).",
                    SigningErrorReason.LevelNotAchievable);
            }

            logger.ExtendedFormApplying(operationId, _options.ExtendedForm.ToString());
            cms = await ApplyExtendedFormAsync(cms, certificate, chain, hashAlg, profile.Timestamp, cancellationToken).ConfigureAwait(false);
            logger.ExtendedFormApplied(operationId, _options.ExtendedForm.ToString(), cms.Length);
        }

        bool hasArchiveTimestamp = false;
        if (ltvEmbedding is not null && profile.Level >= AdesBaselineLevel.Archive)
        {
            try
            {
                cms = await ApplyArchiveTimestampAsync(cms, hashAlg, cancellationToken).ConfigureAwait(false);
                hasArchiveTimestamp = true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                const string archiveMessage = "CAdES archiveTimestampV3 could not be applied.";
                logger.ArchiveTimestampFailed(operationId, ex.Message);
                if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
                {
                    throw new SigningException(archiveMessage, SigningErrorReason.LevelNotAchievable, ex);
                }

                BaselineSigning.AddDowngradeWarnings(warnings, SigningWarningCode.ArchiveTimestampUnavailable,
                    $"{archiveMessage} {ex.Message}");
            }
        }

        (bool baseSignatureValid, bool artifactHasTimestamp, bool artifactHasLtvMaterial, bool artifactHasArchiveTimestamp) = InspectProducedArtifact(
            cms, _data, timestampTokenBytes, ltvEmbedding?.Evidence, hasArchiveTimestamp);
        logger.ReadBackVerified(baseSignatureValid, artifactHasTimestamp, artifactHasLtvMaterial, artifactHasArchiveTimestamp);
        if (!baseSignatureValid)
        {
            throw new SigningException(
                "The completed CMS signature or signed content failed read-back verification.",
                SigningErrorReason.Unspecified);
        }
        if (timestampTokenBytes is not null && !artifactHasTimestamp)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.SignatureTimestampUnavailable,
                "The produced CMS does not contain the requested signature timestamp token.");
        }

        if (ltvEmbedding is not null && !artifactHasLtvMaterial)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.LongTermValidationMaterialUnavailable,
                "The produced CMS does not contain complete LTV attributes.");
        }

        if (hasArchiveTimestamp && !artifactHasArchiveTimestamp)
        {
            BaselineSigning.RequireOrDowngrade(
                profile, warnings, SigningWarningCode.ArchiveTimestampUnavailable,
                "The produced CMS does not contain a valid archiveTimestampV3 covering its ETSI-defined input.");
        }

        var achieved = BaselineSigning.AchievedLevel(artifactHasTimestamp, artifactHasLtvMaterial, artifactHasArchiveTimestamp);

        if (_options.CoSignTarget is { } coSignTarget)
        {
            cms = CmsComposer.AddSigner(coSignTarget, cms);
            logger.CoSignatureAdded(operationId);
        }
        else if (_options.CounterSignTarget is { } counterSignTarget)
        {
            cms = CmsComposer.AddCounterSignature(counterSignTarget, _options.CounterSignIndex, cms);
            logger.CounterSignatureAdded(operationId, _options.CounterSignIndex);
        }

        logger.SigningCompleted(operationId, stopwatch.ElapsedMilliseconds, cms.Length,
            profile.Level.ToString(), achieved.ToString());

        return new CadesSigningResult
        {
            SignedArtifact = cms,
            RequestedLevel = profile.Level,
            AchievedLevel = achieved,
            HasSignatureTimestamp = artifactHasTimestamp,
            HasLongTermValidationMaterial = artifactHasLtvMaterial,
            HasArchiveTimestamp = artifactHasArchiveTimestamp,
            Warnings = warnings.AsReadOnly()
        };
    }

    private static (bool BaseSignatureValid, bool HasTimestamp, bool HasLtvMaterial, bool HasArchiveTimestamp) InspectProducedArtifact(
        byte[] cms,
        byte[] signedData,
        byte[]? expectedTimestampToken,
        LtvCollectionResult? expectedLtvEvidence,
        bool expectedArchiveTimestamp)
    {
        try
        {
            CmsSignedData parsed = CmsParser.Parse(cms);
            CadesValidationResult validation = new CadesSignatureValidator(
                new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false })
                .Validate(cms, signedData);
            bool baseValid = validation.IsSignatureValid && validation.IsIntegrityValid;
            bool hasTimestamp = expectedTimestampToken is not null &&
                validation.HasValidTimestamp == true &&
                parsed.SignatureTimestampToken is not null &&
                CryptographicOperations.FixedTimeEquals(parsed.SignatureTimestampToken, expectedTimestampToken);
            bool hasLtvMaterial = hasTimestamp && expectedLtvEvidence is not null &&
                validation.IsLtvDataValid == true &&
                HasExpectedLtvEvidence(cms, expectedLtvEvidence);
            bool hasArchiveTimestamp = hasLtvMaterial && expectedArchiveTimestamp &&
                validation.HasValidArchiveTimestamp == true &&
                CadesArchiveTimestampV3.Validate(cms, signedData, []);
            return (baseValid, hasTimestamp, hasLtvMaterial, hasArchiveTimestamp);
        }
        catch (Exception)
        {
            return (false, false, false, false);
        }
    }

    internal static bool HasExpectedLtvEvidence(byte[] cms, LtvCollectionResult expectedEvidence)
    {
        if (!expectedEvidence.HasCompleteCoverage ||
            (expectedEvidence.OcspResponses.Count == 0 && expectedEvidence.Crls.Count == 0))
        {
            return false;
        }

        CadesValidationMaterial embedded = CadesValidationMaterial.Read(cms);
        return embedded.HasRevocationSet &&
            ContainsAll(embedded.Certificates, expectedEvidence.CertificateRawData) &&
            ContainsAll(embedded.OcspResponses, expectedEvidence.OcspResponses) &&
            ContainsAll(embedded.Crls, expectedEvidence.Crls) &&
            HasAuthenticatedRevocationEvidence(embedded);
    }

    private static bool HasAuthenticatedRevocationEvidence(CadesValidationMaterial embedded)
    {
        var certificates = new List<X509Certificate2>();
        try
        {
            foreach (byte[] raw in embedded.Certificates)
            {
                certificates.Add(CertificateLoader.LoadCertificate(raw));
            }

            return EmbeddedRevocationEvidence.CoversAll(
                certificates, embedded.OcspResponses, embedded.Crls,
                DateTimeOffset.UtcNow, RevocationEvidence.MatchingOcspClient());
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static bool ContainsAll(IReadOnlyList<byte[]> embeddedValues, IReadOnlyList<byte[]> expectedValues)
    {
        return expectedValues.All(expected =>
            embeddedValues.Any(value => value.AsSpan().SequenceEqual(expected)));
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

        BaselineSigning.EnsureCertificateValidNow(certificate);
    }

    /// <summary>The signer certificate given to WithCertificate or WithExternalSigner, or <see langword="null"/> before either is called. Extensions read it to pick policies.</summary>
    public X509Certificate2? SignerCertificate => _options.Credential is { } credential ? GetCertificate(credential) : null;

    /// <summary>The certificate chain given with the signer certificate (empty when none was given).</summary>
    public IReadOnlyList<X509Certificate2> SignerChain => _options.Credential is { } credential ? GetChain(credential) : [];

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
        HashAlgorithmName hashAlg,
        string sigAlgOid,
        CmsAttribute? contentTimestamp)
    {
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;
        var extraAttributes = BuildSignedAttributesInternal(contentTimestamp);
        byte[]? eContent = _options.ContentType == CadesContentType.Enveloped ? _data : null;

        if (_options.IsCounterSignature)
        {
            string digestOid = CmsSignatureBuilder.GetDigestOid(hashAlg);
            byte[] signedAttrs = CmsSignatureBuilder.BuildSignedAttributes(
                CmsSignatureBuilder.ComputeHash(_data, hashAlg), digestOid, signingTime, certificate, extraAttributes,
                padesAttributes: false, includeContentType: false);
            byte[] signatureValue = CmsSignatureBuilder.SignData(signedAttrs, certificate, hashAlg, sigAlgOid);
            return CmsSignatureBuilder.BuildSignedData(
                digestOid, sigAlgOid, hashAlg, signedAttrs, signatureValue, certificate, [certificate, .. chain]);
        }

        return CmsSignatureBuilder.Build(
            _data, certificate, hashAlg, signingTime,
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
        HashAlgorithmName hashAlg,
        string sigAlgOid,
        RsaPssParameters? rsaPssParameters,
        CmsAttribute? contentTimestamp,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var signingTime = _options.SigningTime ?? DateTimeOffset.UtcNow;
        string digestOid = CmsSignatureBuilder.GetDigestOid(hashAlg);

        byte[] contentHash = CmsSignatureBuilder.ComputeHash(_data, hashAlg);
        var extraAttributes = BuildSignedAttributesInternal(contentTimestamp);

        byte[] signedAttrs = CmsSignatureBuilder.BuildSignedAttributes(
            contentHash, digestOid, signingTime, certificate, extraAttributes,
            padesAttributes: false, includeContentType: !_options.IsCounterSignature);

        var request = new ExternalSigningRequest(
            signedAttrs,
            hashAlg,
            sigAlgOid,
            ExternalSigningPayloadKind.CmsSignedAttributes,
            _options.OperationId,
            rsaPssParameters);
        _options.Dependencies.Logger.ExternalSignerInvoked(signedAttrs.Length);
        ReadOnlyMemory<byte> signature = await BaselineSigning
            .SignExternallyAsync(external.Signer, request, certificate, cancellationToken).ConfigureAwait(false);
        _options.Dependencies.Logger.ExternalSignatureReceived(signature.Length);
        List<X509Certificate2> allCerts = [certificate, .. chain];
        byte[]? eContent = _options.ContentType == CadesContentType.Enveloped ? _data : null;

        return CmsSignatureBuilder.BuildSignedData(
            digestOid, sigAlgOid, hashAlg, signedAttrs,
            signature.ToArray(), certificate, allCerts,
            eContent: eContent);
    }

    /// <summary>
    /// Asks the TSA for a timestamp whose message imprint is the hash of the content
    /// (the eContent of an attached signature, the external data of a detached one).
    /// </summary>
    private async Task<CmsAttribute> RequestContentTimestampAsync(
        TimestampOptions timestamp, HashAlgorithmName hashAlg, string operationId, CancellationToken cancellationToken)
    {
        var logger = _options.Dependencies.Logger;
        try
        {
            logger.TimestampRequested(operationId, timestamp.Endpoint.ToString());
            byte[] token = await CreateTimestampClient(timestamp).GetTimestampAsync(_data, hashAlg, cancellationToken).ConfigureAwait(false);
            TimestampClient.ValidateTimestampToken(token, _data, hashAlg);
            return CmsAttribute.Create(Oids.ContentTimestamp, token);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.TimestampFailed(operationId, ex.Message);
            throw new SigningException($"Content timestamp request failed: {ex.Message}", SigningErrorReason.NetworkFailure, ex);
        }
    }

    private IReadOnlyList<CmsAttribute>? BuildSignedAttributesInternal(CmsAttribute? contentTimestamp)
    {
        var attrs = new List<CmsAttribute>();
        if (contentTimestamp is not null)
        {
            attrs.Add(contentTimestamp);
        }

        if (_options.CommitmentType.HasValue)
        {
            attrs.Add(CmsAttribute.CommitmentTypeIndication(_options.CommitmentType.Value));
        }

        if (_options.SignaturePolicy is not null)
        {
            attrs.Add(CmsAttribute.SignaturePolicyIdentifier(_options.SignaturePolicy));
        }
        else if (_options.SignaturePolicyOid is not null)
        {
            attrs.Add(CmsAttribute.SignaturePolicyIdentifier(
                _options.SignaturePolicyOid, _options.SignaturePolicyUri));
        }

        if (_options.ContentHints is not null)
        {
            attrs.Add(CadesSignedAttributes.EncodeContentHints(_options.ContentHints));
        }

        if (_options.MimeType is not null)
        {
            attrs.Add(CadesSignedAttributes.EncodeMimeType(_options.MimeType));
        }

        if (_options.SignerLocation is not null)
        {
            attrs.Add(CadesSignedAttributes.EncodeSignerLocation(_options.SignerLocation));
        }

        // An empty signer-attributes-v2 shall not be created (§5.2.6.1).
        IReadOnlyList<string> roles = _options.SignerRoles ?? [];
        IReadOnlyList<ReadOnlyMemory<byte>> attributeCertificates = _options.AttributeCertificates ?? [];
        IReadOnlyList<CadesSignedAssertion> signedAssertions = _options.SignedAssertions ?? [];
        if (roles.Count > 0 || attributeCertificates.Count > 0 || signedAssertions.Count > 0)
        {
            attrs.Add(CadesSignedAttributes.EncodeSignerAttributes(roles, attributeCertificates, signedAssertions));
        }

        return attrs.Count > 0 ? attrs : null;
    }

    private async Task<byte[]?> ApplyTimestampAsync(
        byte[] cms,
        HashAlgorithmName hashAlg,
        TimestampOptions timestampOptions,
        CancellationToken cancellationToken)
    {
        var tsaClient = CreateTimestampClient(timestampOptions);
        byte[] signatureValue = TimestampClient.ExtractSignatureValue(cms);
        byte[] tsToken = await tsaClient.GetTimestampAsync(signatureValue, hashAlg, cancellationToken).ConfigureAwait(false);
        TimestampClient.ValidateTimestampToken(tsToken, signatureValue, hashAlg);
        return tsToken;
    }

    private ITimestampClient CreateTimestampClient(TimestampOptions timestampOptions) =>
        BaselineSigning.CreateTimestampClient(
            timestampOptions, _options.Dependencies.TsaFactory, _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger);

    private ITimestampClient CreateTimestampClient(string endpoint, IHttpClientProvider? scopedProvider) =>
        BaselineSigning.CreateTimestampClient(
            endpoint, scopedProvider, _options.Dependencies.TsaFactory, _options.Dependencies.HttpClientProvider, _options.Dependencies.Logger);

    private async Task<byte[]> ApplyExtendedFormAsync(
        byte[] cms,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        HashAlgorithmName hashAlg,
        TimestampOptions timestamp,
        CancellationToken cancellationToken)
    {
        var logger = _options.Dependencies.Logger;
        var known = new List<X509Certificate2> { certificate };
        known.AddRange(chain.Where(c => known.All(k => k.Thumbprint != c.Thumbprint)));
        var provider = timestamp.HttpClientProvider ?? _options.Dependencies.HttpClientProvider;
        var ltvOptions = _options.Profile.LongTermValidation ?? new LongTermValidationOptions();
        var evidence = await LtvDataCollector.CollectAsync(
            provider, certificate, known, logger, ltvOptions, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!evidence.HasCompleteCoverage)
        {
            throw new SigningException(
                "Extended validation data needs the CRL or OCSP response of every certificate in the path; some could not be collected.",
                SigningErrorReason.LevelNotAchievable);
        }

        var path = RevocationEvidence.BuildPath(certificate, [.. evidence.CertificateRawData, .. known.Select(k => k.RawData)]);
        var refs = new List<CmsAttribute>
        {
            CadesExtendedValidationData.CompleteCertificateRefs(path),
            CadesExtendedValidationData.CompleteRevocationRefs(path, evidence.Crls, evidence.OcspResponses),
        };
        cms = CmsSignatureBuilder.AddUnsignedAttributes(cms, refs);
        var tsaClient = CreateTimestampClient(timestamp);

        if (_options.ExtendedForm is CadesExtendedForm.CompleteReferences or CadesExtendedForm.ExtendedLong)
        {
            byte[] escInput = CadesExtendedValidationData.EscTimeStampInput(cms);
            byte[] escToken = await tsaClient.GetTimestampAsync(escInput, hashAlg, cancellationToken).ConfigureAwait(false);
            cms = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Raw(Oids.EscTimeStamp, escToken)]);
        }

        if (_options.ExtendedForm is CadesExtendedForm.ExtendedLong or CadesExtendedForm.Archive)
        {
            cms = CmsSignatureBuilder.AddUnsignedAttributes(cms,
            [
                CadesExtendedValidationData.CertificateValues(path),
                CadesExtendedValidationData.RevocationValues(evidence.Crls, evidence.OcspResponses),
            ]);
        }

        if (_options.ExtendedForm == CadesExtendedForm.Archive)
        {
            byte[] external = _options.ContentType == CadesContentType.Detached ? _data : [];
            byte[] archiveInput = CadesExtendedValidationData.ArchiveTimeStampV2Input(cms, _options.ContentType == CadesContentType.Detached ? external : null);
            byte[] archiveToken = await tsaClient.GetTimestampAsync(archiveInput, hashAlg, cancellationToken).ConfigureAwait(false);
            cms = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Raw(Oids.ArchiveTimeStamp, archiveToken)]);
        }

        return cms;
    }

    private async Task<CadesLtvEmbeddingResult?> ApplyLtvAsync(
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
            ltvProvider, certificate, allKnownCerts, logger, profile.LongTermValidation,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        bool hasLtvMaterial = ltvData.CertificateRawData.Count > 0 && ltvData.HasCompleteCoverage;
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

        byte[] embeddedCms = CmsSignatureBuilder.AddValidationMaterial(
            cms, ltvData.CertificateRawData, ltvData.Crls, ltvData.OcspResponses);
        logger.LtvEmbedded(_options.OperationId ?? "-", ltvData.CertificateRawData.Count, ltvData.Crls.Count, ltvData.OcspResponses.Count);
        return new CadesLtvEmbeddingResult(embeddedCms, ltvData);
    }

    private async Task<byte[]> ApplyArchiveTimestampAsync(
        byte[] cms,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken)
    {
        var profile = _options.Profile;
        var archiveOptions = profile.ArchiveTimestamp;
        var timestampOptions = profile.Timestamp!;
        var endpoint = archiveOptions?.Endpoint ?? timestampOptions.Endpoint;
        var scopedProvider = archiveOptions?.HttpClientProvider ?? timestampOptions.HttpClientProvider;
        byte[] hashIndex = CadesArchiveTimestampV3.CreateHashIndex(cms, hashAlgorithm);
        byte[] input = CadesArchiveTimestampV3.CreateMessageImprintInput(
            cms, _data, hashAlgorithm, hashIndex);
        var tsaClient = CreateTimestampClient(endpoint.ToString(), scopedProvider);
        string operationId = _options.OperationId ?? "-";
        _options.Dependencies.Logger.ArchiveTimestampRequested(operationId, endpoint.ToString());
        byte[] archiveToken = await tsaClient.GetTimestampAsync(input, hashAlgorithm, cancellationToken).ConfigureAwait(false);
        TimestampClient.ValidateTimestampToken(archiveToken, input, hashAlgorithm);
        archiveToken = CadesArchiveTimestampV3.AddHashIndexToTimestampToken(archiveToken, hashIndex);
        byte[] completedCms = CmsSignatureBuilder.AddUnsignedAttributes(
            cms, [CmsAttribute.Raw(Oids.ArchiveTimeStampV3, archiveToken)]);
        var warnings = new List<string>();
        if (!CadesArchiveTimestampV3.Validate(completedCms, _data, warnings))
        {
            throw new SigningException(
                $"The produced archiveTimestampV3 did not validate: {string.Join(" ", warnings)}",
                SigningErrorReason.LevelNotAchievable);
        }

        _options.Dependencies.Logger.ArchiveTimestampEmbedded(operationId, archiveToken.Length);
        return completedCms;
    }

    private CadesSignerBuilder WithCredential(CadesSigningCredential credential) =>
        With(_options with { Credential = credential });

    private sealed record CadesLtvEmbeddingResult(byte[] SignedCms, LtvCollectionResult Evidence);

    private CadesSignerBuilder With(CadesSigningOptions options) =>
        new(_data, options);

    private static IReadOnlyList<X509Certificate2> CopyChain(IReadOnlyList<X509Certificate2> chain) =>
        chain.ToList().AsReadOnly();
}
