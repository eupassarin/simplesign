using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.Core.Validation.Policy;

namespace SimpleSign.CAdES;

/// <summary>Result of a CAdES signature validation.</summary>
public sealed record CadesValidationResult
{
    /// <summary>The cryptographic signature is mathematically valid.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The document integrity is intact (content hash matches).</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>The certificate chain is valid and trusted.</summary>
    public bool IsCertificateChainValid { get; init; }

    /// <summary>The timestamp token's cryptographic integrity and message imprint are valid; independent of TSA trust.</summary>
    public bool? HasValidTimestamp { get; init; }

    /// <summary>Whether the TSA chain is trusted; null when the token is absent, invalid, or no trust policy was evaluated.</summary>
    public bool? IsTsaTrusted { get; init; }

    /// <summary>Root SignedData or legacy CAdES-XL certificate and revocation material is present.</summary>
    public bool? IsLtvDataValid { get; init; }

    /// <summary>The archive timestamp (if present) is valid.</summary>
    public bool? HasValidArchiveTimestamp { get; init; }

    /// <summary>Whether the escTimeStamp (CAdES-X type 1) covers the signature, its timestamp and the complete references; null when absent.</summary>
    public bool? HasValidEscTimestamp { get; init; }

    /// <summary>
    /// The content-time-stamp signed attribute (ETSI EN 319 122-1 §5.2.8) is an intact token whose
    /// message imprint is the hash of the signed content; null when there is none or the content
    /// was not available to check it. TSA trust is not evaluated.
    /// </summary>
    public bool? HasValidContentTimestamp { get; init; }

    /// <summary>The time of the content timestamp, when it is valid: the content existed at this time.</summary>
    public DateTimeOffset? ContentTimestampTime { get; init; }

    /// <summary>The signer certificate.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>Signing time from the signed attributes.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Non-blocking warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>True when all checks pass, the validation policy's constraints included.</summary>
    public bool IsValid =>
        IsIntegrityValid && IsSignatureValid && IsCertificateChainValid && Indication == SignatureIndication.Valid;

    private SignatureIndication? _indication;

    /// <summary>
    /// The ETSI EN 319 102-1 indication, including the validation policy's constraints. Without an
    /// evaluation (a document that could not be read) it follows the integrity, signature and chain checks.
    /// </summary>
    public SignatureIndication Indication
    {
        get => _indication ?? (IsIntegrityValid && IsSignatureValid
            ? (IsCertificateChainValid ? SignatureIndication.Valid : SignatureIndication.Indeterminate)
            : SignatureIndication.Invalid);
        init => _indication = value;
    }

    /// <summary>The ETSI EN 319 102-1 sub-indication of an INVALID or INDETERMINATE result, or null.</summary>
    public SignatureSubIndication? SubIndication { get; init; }

    /// <summary>The checks of the validation and their outcome, including the validation policy's constraints.</summary>
    public IReadOnlyList<ValidationConstraintResult> Constraints { get; init; } = [];

    /// <summary>The validation policy applied (its name and digest), chosen by the signature policy the signature names.</summary>
    public SimpleSign.Core.Policies.AppliedPolicy? AppliedPolicy { get; init; }

    /// <summary>The earliest time the signature is proven to exist (a trusted signature timestamp), or null.</summary>
    public DateTimeOffset? BestSignatureTime { get; init; }

    /// <summary>The qualification of the signature under a legal framework (QESig, AdESig-QC…), from <see cref="ValidationOptions.SignatureQualifiers"/>; null when no qualifier applies.</summary>
    public SignatureQualification? Qualification { get; init; }

    /// <summary>The timestamps and revocation data the validation used, each with the outcome of its own evaluation.</summary>
    public IReadOnlyList<ValidationObjectEntry> ValidationObjects { get; init; } = [];

    /// <summary>
    /// Whether the signing certificate chain is not revoked: null when revocation was not checked by
    /// <c>ValidateAsync</c>; false when a certificate is revoked or the status is unknown (see <see cref="RevocationSource"/>).
    /// </summary>
    public bool? IsNotRevoked { get; init; }

    /// <summary>How revocation was established (<see cref="RevocationSource.CertificateChain"/>) or why it was not.</summary>
    public RevocationSource RevocationSource { get; init; }

    /// <summary>What the validation found, for the revocation step of <c>ValidateAsync</c>.</summary>
    internal ValidationFacts? Facts { get; init; }

    /// <summary>The certificates that may complete the signer and TSA chains (embedded certificates, trust anchors).</summary>
    internal IReadOnlyList<X509Certificate2> ChainCandidates { get; init; } = [];

    /// <summary>The CRLs the signature carries (revocation-values), for the revocation step.</summary>
    internal IReadOnlyList<byte[]> EmbeddedCrls { get; init; } = [];

    /// <summary>The OCSP responses the signature carries (revocation-values), for the revocation step.</summary>
    internal IReadOnlyList<byte[]> EmbeddedOcsps { get; init; } = [];

    /// <summary>The signature timestamp token, for the TSA revocation check.</summary>
    internal byte[]? SignatureTimestampToken { get; init; }
}

/// <summary>
/// Validates standalone CAdES digital signatures (ETSI EN 319 122).
/// Given a detached CMS/PKCS#7 SignedData and the original document,
/// verifies content integrity, cryptographic signature, certificate chain,
/// timestamp (if present), and LTV data (if present).
/// </summary>
public sealed class CadesSignatureValidator : ICadesSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly ILogger? _logger;
    private readonly ICryptoVerifier _cryptoVerifier;
    private readonly ICmsParser _cmsParser;
    private readonly ITimestampValidator _timestampValidator;
    private readonly IChainRevocationChecker _chainRevocationChecker;

    /// <summary>Creates a validator with the specified options.</summary>
    public CadesSignatureValidator(
        ValidationOptions? options = null,
        ILogger? logger = null,
        ICryptoVerifier? cryptoVerifier = null,
        ICmsParser? cmsParser = null,
        ITimestampValidator? timestampValidator = null,
        IChainRevocationChecker? chainRevocationChecker = null)
    {
        _options = (options ?? new ValidationOptions()).WithProfileApplied();
        _logger = logger;
        _chainRevocationChecker = chainRevocationChecker
            ?? new ChainRevocationChecker(Core.Http.DefaultHttpClientProvider.Instance.GetClient(), logger)
            {
                Strategy = _options.Verifier.RevocationStrategy,
                Fallback = _options.Verifier.RevocationFallback,
            };
        _cryptoVerifier = cryptoVerifier ?? new CryptoVerifierService();
        _cmsParser = cmsParser ?? new CmsParserService();
        _timestampValidator = timestampValidator ?? new TimestampValidatorService();
    }

    /// <summary>
    /// Validates the first signer of a CAdES signature. For an attached signature (.p7m) pass
    /// <see langword="null"/> as <paramref name="originalData"/> to validate the encapsulated content.
    /// Use <see cref="ValidateAll"/> for co-signatures and countersignatures. Revocation is not checked here, of the signer chain nor of the TSA chain: with <see cref="ValidationOptions.CheckRevocation"/> on, the result carries a warning saying so; use <c>ValidateAsync</c> to check it.
    /// </summary>
    /// <param name="cmsBytes">DER-encoded CMS/PKCS#7 SignedData.</param>
    /// <param name="originalData">The signed document bytes; null to use the encapsulated content. A detached signature
    /// validated without them is INDETERMINATE / SIGNED_DATA_NOT_FOUND.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    /// <returns>A detailed validation result.</returns>
    public CadesValidationResult Validate(
        byte[] cmsBytes,
        byte[]? originalData,
        IEnumerable<X509Certificate2>? trustAnchors = null)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        if (!TryParse(cmsBytes, out var set, out var failure))
        {
            return failure;
        }

        byte[]? content = originalData ?? set.EncapsulatedContent;
        return set.Signers is [var first, ..]
            ? ValidateSigner(cmsBytes, first, content, (data, errors) => content is null ? DataNotGiven(errors) : VerifyContentHash(content, data, errors), trustAnchors, isFirstSigner: true)
            : Failed("The CMS has no signer.");
    }

    /// <summary>
    /// Validates like <see cref="Validate(byte[], byte[], IEnumerable{X509Certificate2})"/>, then, when
    /// <see cref="ValidationOptions.CheckRevocation"/> is on, checks the revocation of the signer chain and
    /// of the signature timestamp's TSA chain (CRL and OCSP, at the time a trusted timestamp proves).
    /// </summary>
    /// <param name="cmsBytes">The CMS signature.</param>
    /// <param name="originalData">The signed data of a detached signature; null for an attached one.</param>
    /// <param name="trustAnchors">The trust anchors; null uses the options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result with its revocation outcome.</returns>
    public async Task<CadesValidationResult> ValidateAsync(
        byte[] cmsBytes,
        byte[]? originalData,
        IEnumerable<X509Certificate2>? trustAnchors = null,
        CancellationToken cancellationToken = default)
    {
        var anchors = trustAnchors?.ToList();
        return await SimpleSign.Core.Diagnostics.Telemetry.MeasureValidationAsync(
            "CAdES", () => WithRevocationAsync(Validate(cmsBytes, originalData, anchors), cancellationToken),
            r => [r.Indication.ToString()]).ConfigureAwait(false);
    }

    /// <summary>
    /// Validates every signer and countersignature like <see cref="ValidateAll"/>, then, when
    /// <see cref="ValidationOptions.CheckRevocation"/> is on, checks the revocation of each signer chain and TSA chain.
    /// </summary>
    /// <param name="cmsBytes">The CMS signature.</param>
    /// <param name="originalData">The signed data of a detached signature; null for an attached one.</param>
    /// <param name="trustAnchors">The trust anchors; null uses the options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The report, each signer with its revocation outcome.</returns>
    public Task<CadesValidationReport> ValidateAllAsync(
        byte[] cmsBytes,
        byte[]? originalData = null,
        IEnumerable<X509Certificate2>? trustAnchors = null,
        CancellationToken cancellationToken = default) =>
        SimpleSign.Core.Diagnostics.Telemetry.MeasureValidationAsync(
            "CAdES", () => ValidateAllCoreAsync(cmsBytes, originalData, trustAnchors, cancellationToken),
            r => r.Signers.Select(s => s.Result.Indication.ToString()));

    private async Task<CadesValidationReport> ValidateAllCoreAsync(
        byte[] cmsBytes,
        byte[]? originalData,
        IEnumerable<X509Certificate2>? trustAnchors,
        CancellationToken cancellationToken)
    {
        var report = ValidateAll(cmsBytes, originalData, trustAnchors?.ToList());
        if (!_options.ChecksRevocation)
        {
            return report;
        }

        var signers = new List<CadesSignerValidationResult>(report.Signers.Count);
        foreach (var signer in report.Signers)
        {
            signers.Add(await WithRevocationAsync(signer, cancellationToken).ConfigureAwait(false));
        }

        return new CadesValidationReport { Signers = signers, Errors = report.Errors };
    }

    private async Task<CadesSignerValidationResult> WithRevocationAsync(CadesSignerValidationResult signer, CancellationToken cancellationToken)
    {
        var counterSignatures = new List<CadesSignerValidationResult>(signer.CounterSignatures.Count);
        foreach (var counter in signer.CounterSignatures)
        {
            counterSignatures.Add(await WithRevocationAsync(counter, cancellationToken).ConfigureAwait(false));
        }

        return new CadesSignerValidationResult
        {
            Index = signer.Index,
            Result = await WithRevocationAsync(signer.Result, cancellationToken).ConfigureAwait(false),
            CounterSignatures = counterSignatures,
        };
    }

    private async Task<CadesValidationResult> WithRevocationAsync(CadesValidationResult result, CancellationToken cancellationToken)
    {
        // An untrusted chain is not checked unless asked (VerifierOptions.CheckRevocationForUntrustedChains).
        if (result.Facts is null
            || !_options.ChecksRevocationFor(result.Facts.IsChainAnchored))
        {
            return result;
        }

        var (facts, evaluation, revocationWarnings) = await RevocationStep.RunAsync(
            result.Facts, result.ChainCandidates, result.SignatureTimestampToken, _chainRevocationChecker,
            result.EmbeddedCrls, result.EmbeddedOcsps, _options.PolicyFor(result.Facts.SignaturePolicyOid), cancellationToken).ConfigureAwait(false);
        return Qualified(result with
        {
            Indication = evaluation.Indication,
            SubIndication = evaluation.SubIndication,
            Constraints = evaluation.Constraints,
            ValidationObjects = evaluation.ValidationObjects,
            AppliedPolicy = evaluation.Policy,
            BestSignatureTime = evaluation.BestSignatureTime,
            Facts = facts,
            IsNotRevoked = facts.IsNotRevoked,
            RevocationSource = facts.RevocationSource,
            IsTsaTrusted = facts.IsTsaTrusted,
            Warnings = [.. result.Warnings.Where(w => w != RevocationStep.NotCheckedWarning), .. revocationWarnings],
        });
    }

    /// <summary>
    /// Validates the first signer against the hash of the signed document, without the document
    /// (e.g. when only its hash was kept). The hash must use the signature's digest algorithm.
    /// </summary>
    /// <param name="cmsBytes">DER-encoded CMS/PKCS#7 SignedData.</param>
    /// <param name="contentHash">The hash of the signed document.</param>
    /// <param name="hashAlgorithmOid">The OID of the hash algorithm of <paramref name="contentHash"/>.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    public CadesValidationResult ValidateWithHash(
        byte[] cmsBytes,
        byte[] contentHash,
        string hashAlgorithmOid,
        IEnumerable<X509Certificate2>? trustAnchors = null)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        ArgumentNullException.ThrowIfNull(contentHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithmOid);
        if (!TryParse(cmsBytes, out var set, out var failure))
        {
            return failure;
        }

        if (set.Signers is not [var first, ..])
        {
            return Failed("The CMS has no signer.");
        }

        return ValidateSigner(cmsBytes, first, null, (data, errors) =>
        {
            if (data.DigestAlgorithmOid != hashAlgorithmOid)
            {
                errors.Add($"The hash uses {hashAlgorithmOid}, but the signature digest algorithm is {data.DigestAlgorithmOid}.");
                return false;
            }

            bool valid = CryptographicOperations.FixedTimeEquals(contentHash, data.MessageDigest);
            if (!valid)
            {
                errors.Add("Content hash mismatch — the document has been altered since signing.");
            }

            return valid;
        }, trustAnchors, isFirstSigner: true);
    }

    /// <summary>
    /// Validates every signer of a CAdES signature (co-signatures) and, under each, its
    /// countersignatures (each checked against its parent's signature value). Revocation is not checked here, of the signer chain nor of the TSA chain: with <see cref="ValidationOptions.CheckRevocation"/> on, the result carries a warning saying so; use <c>ValidateAsync</c> to check it.
    /// </summary>
    /// <param name="cmsBytes">DER-encoded CMS/PKCS#7 SignedData.</param>
    /// <param name="originalData">The signed document bytes; null to use the encapsulated content.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    public CadesValidationReport ValidateAll(
        byte[] cmsBytes,
        byte[]? originalData = null,
        IEnumerable<X509Certificate2>? trustAnchors = null)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        if (!TryParse(cmsBytes, out var set, out var failure))
        {
            return new CadesValidationReport { Errors = failure.Errors };
        }

        byte[]? content = originalData ?? set.EncapsulatedContent;
        var signers = new List<CadesSignerValidationResult>();
        for (int i = 0; i < set.Signers.Count; i++)
        {
            var signer = set.Signers[i];
            var result = ValidateSigner(cmsBytes, signer, content, (data, errors) => content is null ? DataNotGiven(errors) : VerifyContentHash(content, data, errors), trustAnchors, isFirstSigner: i == 0);
            signers.Add(new CadesSignerValidationResult
            {
                Index = i,
                Result = result,
                CounterSignatures = ValidateCounterSignatures(signer, trustAnchors, depth: 0),
            });
        }

        return new CadesValidationReport { Signers = signers.AsReadOnly() };
    }

    private IReadOnlyList<CadesSignerValidationResult> ValidateCounterSignatures(
        CmsSignedData parent, IEnumerable<X509Certificate2>? trustAnchors, int depth)
    {
        if (parent.CounterSignatures.Count == 0 || parent.Signature is null || depth > 8)
        {
            return [];
        }

        var results = new List<CadesSignerValidationResult>();
        for (int i = 0; i < parent.CounterSignatures.Count; i++)
        {
            var counter = parent.CounterSignatures[i];
            byte[] parentSignature = parent.Signature;
            var result = ValidateSigner(null, counter, null, (data, errors) => VerifyContentHash(parentSignature, data, errors), trustAnchors, isFirstSigner: false, isCounterSignature: true);
            results.Add(new CadesSignerValidationResult
            {
                Index = i,
                Result = result,
                CounterSignatures = ValidateCounterSignatures(counter, trustAnchors, depth + 1),
            });
        }

        return results.AsReadOnly();
    }

    private bool TryParse(byte[] cmsBytes, out CmsSignedDataSet set, out CadesValidationResult failure)
    {
        try
        {
            set = _cmsParser.ParseAll(cmsBytes, _logger);
            failure = null!;
            return true;
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            set = null!;
            failure = Failed($"Failed to parse CMS: {ex.Message}");
            return false;
        }
    }

    private static CadesValidationResult Failed(string error) => new() { Errors = [error] };

    /// <summary>The signature and archive timestamps of a signer, for the Timestamp context of the policy.</summary>
    private IReadOnlyList<TimestampTokenFacts>? TimestampTokens(
        CmsSignedData cmsData, bool? tsValid, bool? tsaTrusted, byte[]? archiveToken, bool? archiveTsValid, bool archiveV3,
        IEnumerable<X509Certificate2>? trustAnchors, byte[]? contentToken, bool? contentValid)
    {
        var tokens = new List<TimestampTokenFacts>();
        if (contentToken is not null && contentValid is not null)
        {
            tokens.Add(new TimestampTokenFacts(TimestampTokenKind.Content, contentToken, contentValid,
                TimedTrust.TokenChains(contentToken, trustAnchors ?? _options.TrustedRoots, _options)));
        }

        if (cmsData.SignatureTimestampToken is { } signatureToken && _options.ValidatesTimestamps)
        {
            // Without anchors given to this call, the TSA is judged against the configured roots, as the content and
            // archive timestamps are, so the token's constraints are evaluated.
            tokens.Add(new TimestampTokenFacts(TimestampTokenKind.Signature, signatureToken, tsValid,
                tsaTrusted ?? TimedTrust.TokenChains(signatureToken, trustAnchors ?? _options.TrustedRoots, _options)));
        }

        // An archive timestamp whose TSA cannot be judged (no anchors) is left out rather than reported as untrusted.
        if (archiveToken is not null && archiveTsValid is not null
            && TimedTrust.TokenChains(archiveToken, trustAnchors ?? _options.TrustedRoots, _options) is { } archiveTrusted)
        {
            tokens.Add(new TimestampTokenFacts(TimestampTokenKind.Archive, archiveToken, archiveTsValid, archiveTrusted,
                AtsHashIndexValid: archiveV3 ? archiveTsValid : null));
        }

        return tokens.Count == 0 ? null : tokens;
    }

    /// <summary>The CAdES format and level of a signer, from the attributes it carries.</summary>
    private static string CadesFormat(CmsSignedData cms)
    {
        bool Has(string oid) => cms.UnsignedAttributes?.ContainsKey(oid) == true;
        return cms.SigningCertificateHash is null ? "CMS-NOT-ETSI"
            : cms.SignatureTimestampToken is null ? "CAdES-BASELINE-B"
            : !(Has("1.2.840.113549.1.9.16.2.23") && Has("1.2.840.113549.1.9.16.2.24")) ? "CAdES-BASELINE-T"
            : cms.ArchiveTimestampToken is not null || Has(Oids.ArchiveTimeStamp) || Has(Oids.ArchiveTimeStampV3) ? "CAdES-BASELINE-LTA"
            : "CAdES-BASELINE-LT";
    }

    /// <summary>Validates one signer; <paramref name="cmsBytes"/>/<paramref name="content"/> null skip the SignedData-level (LTV, archive) checks.</summary>
    private CadesValidationResult ValidateSigner(
        byte[]? cmsBytes,
        CmsSignedData cmsData,
        byte[]? content,
        Func<CmsSignedData, List<string>, bool> verifyIntegrity,
        IEnumerable<X509Certificate2>? trustAnchors,
        bool isFirstSigner,
        bool isCounterSignature = false)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        if (cmsData.SignerCertificate is null)
        {
            errors.Add("No signer certificate found in CMS.");
        }

        if (cmsData.MessageDigest is null)
        {
            errors.Add("No messageDigest attribute found in signed attributes.");
        }

        if (errors.Count > 0)
        {
            return new CadesValidationResult { Errors = errors.AsReadOnly() };
        }

        // 2. Verify content integrity (hash match)
        bool integrityValid = verifyIntegrity(cmsData, errors);
        // 3. Verify cryptographic signature
        bool sigValid = _cryptoVerifier.VerifySignature(cmsData, _logger);
        if (!sigValid)
        {
            errors.Add("Cryptographic signature verification failed.");
        }

        // 4. Validate signingCertificateV2 binding
        if (cmsData.SigningCertificateHash is not null && cmsData.SignerCertificate is not null)
        {
            _cryptoVerifier.ValidateSigningCertV2(cmsData, errors, _logger);
        }

        // 5. Certificate chain validation (intermediates come from the CMS certificates field)
        int chainErrorsStart = errors.Count;
        bool chainValid = ValidateChain(cmsData.SignerCertificate!, errors, warnings, trustAnchors, cmsData.Certificates, out bool chainAnchored);
        int chainErrorsCount = errors.Count - chainErrorsStart;

        // 6. Timestamp validation
        bool? tsValid = null;
        bool? tsaTrusted = null;
        DateTimeOffset? provenTime = null;
        DateTimeOffset? signatureTimestampTime = null;
        if (cmsData.SignatureTimestampToken is not null && _options.ValidatesTimestamps)
        {
            bool judgesTsa = trustAnchors is not null || _options.TrustedRoots is { Count: > 0 } || TimedTrust.IsConfigured(_options);
            TimestampValidator.CertificateChainValidatorDelegate? tsaPolicy = !judgesTsa ? null :
                (certificate, certificates, tsaErrors, tsaWarnings) =>
                {
                    if (certificate is null)
                    {
                        tsaErrors.Add("TSA signer certificate is missing.");
                        return false;
                    }

                    return ValidateChain(certificate, tsaErrors, tsaWarnings, trustAnchors, certificates, out _);
                };
            TimestampTokenValidationResult timestamp = TimedTrust.TrustTsaAtGenTime(
                _timestampValidator.ValidateWithTrust(cmsData, warnings, tsaPolicy, _logger),
                cmsData.SignatureTimestampToken, _options, warnings);
            tsValid = timestamp.IsIntegrityValid;
            tsaTrusted = timestamp.IsTsaTrusted;
            provenTime = timestamp is { IsIntegrityValid: true, IsTsaTrusted: true } ? timestamp.GenTime : null;
            signatureTimestampTime = timestamp.GenTime;
        }

        // 6a. content-time-stamp: a signed attribute whose token covers the content itself
        bool? contentTsValid = null;
        DateTimeOffset? contentTsTime = null;
        byte[]? contentTimestampToken = ReadSignedAttribute(cmsData.SignedAttrs, Oids.ContentTimestamp);
        if (contentTimestampToken is { } contentToken)
        {
            if (content is null)
            {
                warnings.Add("The content timestamp was not validated (it needs the signed content).");
            }
            else
            {
                var verification = TimestampToken.Verify(contentToken, content);
                contentTsValid = verification.IsImprintValid && verification.IsIntegrityValid;
                if (contentTsValid == true)
                {
                    contentTsTime = verification.Info?.GenerationTime;
                }
                else
                {
                    errors.Add(verification.IsImprintValid
                        ? "content-time-stamp is not an intact timestamp token."
                        : "content-time-stamp does not cover the signed content.");
                }
            }
        }

        // 7. LTV data validation (root SignedData certificate and revocation sets)
        bool? ltvValid = cmsBytes is null || !_options.ValidatesLongTermData ? null : ValidateLtvData(cmsBytes, cmsData, warnings);
        var embedded = _options.ValidatesLongTermData
            ? EmbeddedRevocationValues.Read(cmsData.UnsignedAttributes?.GetValueOrDefault(Oids.RevocationValues))
            : ([], []);

        // 7a. escTimeStamp (CAdES-X type 1, RFC 5126 §5.11.3)
        bool? escValid = null;
        if (cmsBytes is not null && isFirstSigner && cmsData.UnsignedAttributes?.TryGetValue(Oids.EscTimeStamp, out byte[][]? esc) == true && esc.Length > 0)
        {
            escValid = TimestampCovers(esc[0], CadesExtendedValidationData.EscTimeStampInput(cmsBytes), cmsData.DigestAlgorithmOid);
            if (escValid == false)
            {
                errors.Add("escTimeStamp does not cover the signature, its timestamp and the complete references.");
            }
        }

        // 8. Archive timestamp validation (covers the first signer of the SignedData)
        bool? archiveTsValid = null;
        byte[]? archiveToken = null;
        bool archiveV3 = false;
        if (!_options.ValidatesArchivalData)
        {
            // Below ValidationLevel.ArchivalData the archive timestamps are not looked at.
        }
        else if (cmsBytes is not null && content is not null && isFirstSigner
            && cmsData.UnsignedAttributes?.TryGetValue(Oids.ArchiveTimeStamp, out byte[][]? archiveV2) == true && archiveV2.Length > 0)
        {
            archiveTsValid = TimestampCovers(archiveV2[0], CadesExtendedValidationData.ArchiveTimeStampV2Input(cmsBytes, content), cmsData.DigestAlgorithmOid);
            archiveToken = archiveV2[0];
            if (archiveTsValid == false)
            {
                errors.Add("archive-time-stamp (v2) does not cover the signature and its validation data.");
            }
        }
        else if (cmsData.ArchiveTimestampToken is not null)
        {
            if (cmsBytes is not null && content is not null && isFirstSigner)
            {
                archiveTsValid = ValidateArchiveTimestamp(cmsBytes, content, cmsData, warnings);
                archiveToken = cmsData.ArchiveTimestampToken;
                archiveV3 = true;
            }
            else
            {
                warnings.Add("The archive timestamp was not validated (it needs the signed content and is checked for the first signer only).");
            }
        }

        // 8a. Past signature validation (EN 319 102-1 §5.6): a trusted archive time-stamp proves the signature
        // time-stamp existed while its TSA's certificate was valid, so it keeps its proof of existence after that
        // certificate expired.
        if (tsValid == true && tsaTrusted != true && archiveTsValid == true && archiveToken is not null
            && TimedTrust.TrustTsaAtLaterProof(signatureTimestampTime, cmsData.SignatureTimestampToken, archiveToken,
                trustAnchors ?? _options.TrustedRoots, _options, warnings))
        {
            tsaTrusted = true;
            provenTime = signatureTimestampTime;
        }

        // 8b. Not anchored today: the anchors of the proof of existence (a trusted-list service withdrawn since).
        if (!chainAnchored && provenTime is { } proven && TimedTrust.IsConfigured(_options) && cmsData.SignerCertificate is { } signerAtTime)
        {
            var timedErrors = new List<string>();
            var timedWarnings = new List<string>();
            IEnumerable<X509Certificate2> anchorsThen = [.. trustAnchors ?? [], .. TimedTrust.AnchorsAt(_options, proven)];
            bool timedValid = ValidateChain(signerAtTime, timedErrors, timedWarnings, anchorsThen, cmsData.Certificates, out bool timedAnchored);
            if (timedAnchored)
            {
                errors.RemoveRange(chainErrorsStart, chainErrorsCount);
                errors.InsertRange(chainErrorsStart, timedErrors);
                warnings.AddRange(timedWarnings);
                warnings.Add(TimedTrust.SignerWarning(proven));
                (chainValid, chainAnchored) = (timedValid, true);
            }
        }

        var facts = new ValidationFacts
        {
            IsIntegrityValid = integrityValid,
            IsSignatureValid = sigValid,
            SignerCertificate = cmsData.SignerCertificate,
            IsCertificateChainValid = chainValid,
            IsTsaTrusted = tsaTrusted,
            DigestAlgorithmOid = cmsData.DigestAlgorithmOid,
            ProofOfExistence = provenTime,
            ChainReachesAnchor = chainAnchored,
            SignedDataFound = content is not null || integrityValid,
            CoversWholeDocument = integrityValid ? true : null,
            SignatureFormat = CadesFormat(cmsData),
            UnsignedAttributes = CmsValidationFacts.UnsignedOf(cmsData) with
            {
                TLevelTimeStampValid = provenTime is not null,
                LtaLevelTimeStampValid = archiveTsValid,
            },
            EmbeddedCrls = embedded.Crls,
            EmbeddedOcsps = embedded.Ocsps,
            IsCounterSignature = isCounterSignature,
            TrustedLists = _options.TrustedLists,
            Timestamps = TimestampTokens(cmsData, tsValid, tsaTrusted, archiveToken, archiveTsValid, archiveV3, trustAnchors, contentTimestampToken, contentTsValid),
            PolicyDocumentAvailable = _options.PolicyDocumentFound(cmsData.SignaturePolicyOid),
        }.WithCms(cmsData, _options.TrustedRoots);
        var evaluation = ValidationPolicyEvaluator.Evaluate(facts, _options.PolicyFor(facts.SignaturePolicyOid));
        warnings.AddRange(evaluation.Warnings);
        if (_options.ChecksRevocationFor(facts.IsChainAnchored))
        {
            warnings.Add(RevocationStep.NotCheckedWarning);
        }

        return Qualified(new CadesValidationResult
        {
            Indication = evaluation.Indication,
            SubIndication = evaluation.SubIndication,
            Constraints = evaluation.Constraints,
            ValidationObjects = evaluation.ValidationObjects,
            AppliedPolicy = evaluation.Policy,
            BestSignatureTime = evaluation.BestSignatureTime,
            Facts = facts,
            ChainCandidates = [.. cmsData.Certificates, .. trustAnchors ?? [], .. _options.TrustedRoots ?? []],
            EmbeddedCrls = embedded.Crls,
            EmbeddedOcsps = embedded.Ocsps,
            SignatureTimestampToken = cmsData.SignatureTimestampToken,
            IsSignatureValid = sigValid,
            IsIntegrityValid = integrityValid,
            IsCertificateChainValid = chainValid,
            HasValidTimestamp = tsValid,
            IsTsaTrusted = tsaTrusted,
            IsLtvDataValid = ltvValid,
            HasValidArchiveTimestamp = archiveTsValid,
            HasValidEscTimestamp = escValid,
            HasValidContentTimestamp = contentTsValid,
            ContentTimestampTime = contentTsTime,
            SignerCertificate = cmsData.SignerCertificate,
            SigningTime = cmsData.SigningTime,
            Errors = errors.AsReadOnly(),
            Warnings = warnings.Count > 0 ? warnings.AsReadOnly() : []
        });
    }

    /// <summary>The result with its qualification under a legal framework, when the options have qualifiers.</summary>
    private CadesValidationResult Qualified(CadesValidationResult result) =>
        result.SignerCertificate is { } signer && _options.SignatureQualifiers is { Count: > 0 }
            ? result with
            {
                Qualification = _options.Qualify(new SimpleSign.Core.Extensions.SignatureQualificationContext(signer, result.Indication)
                {
                    Certificates = [.. result.ChainCandidates],
                    ClaimedSigningTime = result.SigningTime,
                    BestSignatureTime = result.BestSignatureTime,
                    ValidationObjects = result.ValidationObjects,
                    Format = "CAdES",
                }),
            }
            : result;


    /// <summary>The first value of a signed attribute, DER-encoded; null when the attribute is absent or the set is malformed.</summary>
    private static byte[]? ReadSignedAttribute(byte[]? signedAttrs, string oid)
    {
        if (signedAttrs is null)
        {
            return null;
        }

        try
        {
            var set = new AsnReader(signedAttrs, AsnEncodingRules.BER).ReadSetOf(skipSortOrderValidation: true);
            while (set.HasData)
            {
                var attribute = set.ReadSequence();
                if (attribute.ReadObjectIdentifier() == oid)
                {
                    var values = attribute.ReadSetOf(skipSortOrderValidation: true);
                    return values.HasData ? values.ReadEncodedValue().ToArray() : null;
                }
            }
        }
        catch (AsnContentException)
        {
            // Malformed attributes: treated as absent.
        }

        return null;
    }

    /// <summary>Whether the RFC 3161 token's message imprint is the hash of <paramref name="data"/>.</summary>
    private static bool TimestampCovers(byte[] token, byte[] data, string digestOid)
    {
        try
        {
            TimestampClient.ValidateTimestampToken(token, data, HashFromOid(digestOid));
            return true;
        }
        // S2221: intentional -- validation pipeline converts exceptions to results
        catch (Exception)
        {
            return false;
        }
    }

    private static HashAlgorithmName HashFromOid(string oid) => oid switch
    {
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
        Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
        Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
        _ => HashAlgorithmName.SHA256,
    };

    /// <summary>A detached signature validated without its data: nothing to compare, and the policy says SIGNED_DATA_NOT_FOUND.</summary>
    private static bool DataNotGiven(List<string> errors)
    {
        errors.Add("The signature is detached and its signed data was not given: its integrity cannot be checked.");
        return false;
    }

    private static bool VerifyContentHash(byte[] originalData, CmsSignedData cmsData, List<string> errors)
    {
        byte[] actualHash = cmsData.DigestAlgorithmOid switch
        {
            Oids.Sha256 => SHA256.HashData(originalData),
            Oids.Sha384 => SHA384.HashData(originalData),
            Oids.Sha512 => SHA512.HashData(originalData),
            Oids.Sha3_256 => SHA3_256.HashData(originalData),
            Oids.Sha3_384 => SHA3_384.HashData(originalData),
            Oids.Sha3_512 => SHA3_512.HashData(originalData),
            _ => SHA256.HashData(originalData)
        };

        bool valid = actualHash.AsSpan().SequenceEqual(cmsData.MessageDigest!);
        if (!valid)
        {
            errors.Add("Content hash mismatch — the document has been altered since signing.");
        }

        return valid;
    }

    private bool ValidateChain(
        X509Certificate2 signerCert,
        List<string> errors,
        List<string> warnings,
        IEnumerable<X509Certificate2>? trustAnchors,
        IReadOnlyList<X509Certificate2>? additionalCertificates,
        out bool reachesAnchor)
    {
        reachesAnchor = false;
        try
        {
            bool hasCustomRoots = trustAnchors is not null
                || (_options.TrustedRoots is { Count: > 0 })
                || !_options.TrustSystemRoots;

            using var chain = new X509Chain();
            CryptoUtility.ConfigureChainPolicy(chain, _options.NetworkTimeout);
            chain.ChainPolicy.DisableCertificateDownloads = !_options.Verifier.UseAia;
            if (additionalCertificates is not null)
            {
                foreach (X509Certificate2 certificate in additionalCertificates)
                {
                    chain.ChainPolicy.ExtraStore.Add(certificate);
                }
            }

            if (hasCustomRoots)
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationFlags =
                    X509VerificationFlags.IgnoreEndRevocationUnknown |
                    X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;

                AddTrustAnchors(chain, trustAnchors);
                AddTrustAnchors(chain, _options.TrustedRoots);
            }

            bool built = chain.Build(signerCert);
            reachesAnchor = CryptoUtility.ReachesTrustAnchor(chain, built);

            foreach (var element in chain.ChainElements)
            {
                foreach (var status in element.ChainElementStatus)
                {
                    string msg = $"{status.Status}: {status.StatusInformation}".TrimEnd('.');
                    if (status.Status is X509ChainStatusFlags.RevocationStatusUnknown
                        or X509ChainStatusFlags.OfflineRevocation)
                    {
                        warnings.Add(msg);
                    }
                    else if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        errors.Add(msg);
                    }
                }
            }

            return built;
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            errors.Add($"Chain validation error: {ex.Message}");
            return false;
        }
    }

    private static void AddTrustAnchors(X509Chain chain, IEnumerable<X509Certificate2>? anchors)
    {
        if (anchors is null)
        {
            return;
        }

        foreach (var cert in anchors)
        {
            if (cert.IsSelfSigned())
            {
                chain.ChainPolicy.CustomTrustStore.Add(cert);
            }
            else
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }
        }
    }

    private static bool? ValidateLtvData(byte[] cmsBytes, CmsSignedData cmsData, List<string> warnings)
    {
        try
        {
            CadesValidationMaterial material = CadesValidationMaterial.Read(cmsBytes);
            if (!material.HasRevocationSet)
            {
                return ValidateLegacyLtvData(cmsData, warnings);
            }
            if (material.Certificates.Count == 0 ||
                material.Crls.Count == 0 && material.OcspResponses.Count == 0)
            {
                warnings.Add("CAdES-B-LT: Root SignedData lacks certificates or revocation information.");
                return false;
            }
            if (cmsData.SignerCertificate is null ||
                !material.Certificates.Any(cert => cert.AsSpan().SequenceEqual(cmsData.SignerCertificate.RawData)))
            {
                warnings.Add("CAdES-B-LT: Root SignedData does not include the signer certificate.");
                return false;
            }

            var tsaCertificates = TsaCertificateExtractor.ExtractCertificates(cmsData.SignatureTimestampToken);
            try
            {
                if (!tsaCertificates.All(tsa => material.Certificates.Any(cert =>
                    cert.AsSpan().SequenceEqual(tsa.RawData))))
                {
                    warnings.Add("CAdES-B-LT: Root SignedData does not include the signature timestamp certificates.");
                    return false;
                }
            }
            finally
            {
                foreach (var tsaCertificate in tsaCertificates)
                {
                    tsaCertificate.Dispose();
                }
            }

            var certificates = new List<X509Certificate2>();
            try
            {
                foreach (byte[] raw in material.Certificates)
                {
                    certificates.Add(CertificateLoader.LoadCertificate(raw));
                }

                if (!EmbeddedRevocationEvidence.CoversAll(
                    certificates, material.OcspResponses, material.Crls,
                    cmsData.SigningTime ?? DateTimeOffset.UtcNow, RevocationEvidence.MatchingOcspClient()))
                {
                    warnings.Add("CAdES-B-LT: Embedded revocation evidence is not authenticated or does not cover the certificate paths.");
                    return false;
                }
            }
            finally
            {
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
            }

            return true;
        }
        // S2221: validation converts malformed external CMS into a structured result.
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LT: Failed to inspect root validation material: {ex.Message}");
            return false;
        }
    }

    private static bool? ValidateLegacyLtvData(CmsSignedData cmsData, List<string> warnings)
    {
        if (cmsData.UnsignedAttributes is null ||
            !cmsData.UnsignedAttributes.ContainsKey(Oids.CertValues) &&
            !cmsData.UnsignedAttributes.ContainsKey(Oids.RevocationValues))
        {
            return null;
        }

        if (!cmsData.UnsignedAttributes.TryGetValue(Oids.CertValues, out byte[][]? certificateValues) ||
            !cmsData.UnsignedAttributes.TryGetValue(Oids.RevocationValues, out byte[][]? revocationValues) ||
            certificateValues.Length == 0 || revocationValues.Length == 0)
        {
            warnings.Add("CAdES-XL: CertificateValues or RevocationValues is missing.");
            return false;
        }

        bool hasSigner = certificateValues.Any(value =>
            cmsData.SignerCertificate is not null &&
            value.AsSpan().SequenceEqual(cmsData.SignerCertificate.RawData));
        if (!hasSigner)
        {
            warnings.Add("CAdES-XL: CertificateValues does not include the signer certificate.");
        }

        return true;
    }

    private static bool ValidateArchiveTimestamp(
        byte[] cmsBytes, byte[] originalData, CmsSignedData cmsData, List<string> warnings)
    {
        byte[]? archiveToken = cmsData.ArchiveTimestampToken;
        if (archiveToken is null)
        {
            warnings.Add("CAdES-B-LTA: No archive timestamp token found.");
            return false;
        }

        try
        {
            return CadesArchiveTimestampV3.Validate(cmsBytes, originalData, warnings);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LTA: Failed to validate archive timestamp: {ex.Message}");
            return false;
        }
    }
}
