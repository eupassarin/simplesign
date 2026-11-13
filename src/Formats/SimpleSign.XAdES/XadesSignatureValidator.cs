using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.XAdES.Constants;
using SimpleSign.XAdES.Internal;

namespace SimpleSign.XAdES;

/// <summary>
/// Validates XAdES digital signatures (ETSI EN 319 132).
/// Verifies XMLDSig integrity, certificate chain, timestamp tokens, and LTV data.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XadesSignatureValidator : IXadesSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly ITimestampValidator _timestampValidator;
    private readonly IChainRevocationChecker _chainRevocationChecker;
    private readonly ILogger _logger;

    private sealed record XadesPropertyExtractionResult(
        bool HasSignedProperties,
        bool HasSignatureTimeStamp,
        bool HasCertificateValues,
        bool HasRevocationValues,
        bool HasArchiveTimeStamp,
        DateTimeOffset? SigningTime,
        X509Certificate2? SignerCert,
        string SignatureId);

    private static byte[] DecodeBase64(XmlNode el) =>
        Convert.FromBase64String(el.InnerText.Trim());

    /// <summary>Creates a new XAdES signature validator with optional options.</summary>
    /// <param name="options">Validation options; defaults apply when <see langword="null"/>.</param>
    /// <param name="timestampValidator">Timestamp validator; the built-in one is used when <see langword="null"/>.</param>
    /// <param name="logger">Receives diagnostics of each validation; nothing is logged when <see langword="null"/>.</param>
    /// <param name="chainRevocationChecker">The revocation checker of <c>ValidateAsync</c>; one on the default HTTP client when <see langword="null"/>.</param>
    public XadesSignatureValidator(
        ValidationOptions? options = null,
        ITimestampValidator? timestampValidator = null,
        ILogger? logger = null,
        IChainRevocationChecker? chainRevocationChecker = null)
    {
        _options = (options ?? new ValidationOptions()).WithProfileApplied();
        _timestampValidator = timestampValidator ?? new TimestampValidatorService();
        _logger = logger ?? NullLogger.Instance;
        _chainRevocationChecker = chainRevocationChecker
            ?? new ChainRevocationChecker(Core.Http.DefaultHttpClientProvider.Instance.GetClient(), _logger)
            {
                Strategy = _options.Verifier.RevocationStrategy,
                Fallback = _options.Verifier.RevocationFallback,
            };
    }

    /// <summary>
    /// Validates like <see cref="Validate(byte[], IEnumerable{X509Certificate2}, byte[])"/>, then, when
    /// <see cref="ValidationOptions.CheckRevocation"/> is on, checks the revocation of the signer chain and of the
    /// signature timestamp's TSA chain (CRL and OCSP, at the time a trusted timestamp proves).
    /// </summary>
    /// <param name="signedXml">The signed XML document.</param>
    /// <param name="trustAnchors">The trust anchors; null uses the options.</param>
    /// <param name="originalData">The signed data of a detached signature.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result with its revocation outcome.</returns>
    public Task<XadesValidationResult> ValidateAsync(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors = null,
        byte[]? originalData = null,
        CancellationToken cancellationToken = default)
    {
        var anchors = trustAnchors?.ToList();
        return SimpleSign.Core.Diagnostics.Telemetry.MeasureValidationAsync(
            "XAdES", () => WithRevocationAsync(Validate(signedXml, anchors, originalData), cancellationToken), r => [r.Indication.ToString()]);
    }

    /// <summary>
    /// Validates like <see cref="Validate(byte[], IEnumerable{X509Certificate2}, IReadOnlyDictionary{string, byte[]})"/>,
    /// then checks the revocation of the signer and TSA chains when <see cref="ValidationOptions.CheckRevocation"/> is on.
    /// </summary>
    /// <param name="signedXml">The signed XML document.</param>
    /// <param name="trustAnchors">The trust anchors; null uses the options.</param>
    /// <param name="externalData">The detached data objects, by reference URI.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result with its revocation outcome.</returns>
    public Task<XadesValidationResult> ValidateAsync(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors,
        IReadOnlyDictionary<string, byte[]> externalData,
        CancellationToken cancellationToken = default)
    {
        var anchors = trustAnchors?.ToList();
        return SimpleSign.Core.Diagnostics.Telemetry.MeasureValidationAsync(
            "XAdES", () => WithRevocationAsync(Validate(signedXml, anchors, externalData), cancellationToken), r => [r.Indication.ToString()]);
    }

    /// <summary>
    /// Validates every signature of the document like <c>ValidateAll</c>, then, when
    /// <see cref="ValidationOptions.CheckRevocation"/> is on, checks the revocation of each signer chain and TSA
    /// chain, countersignatures included.
    /// </summary>
    /// <param name="signedXml">The signed XML document.</param>
    /// <param name="trustAnchors">The trust anchors; null uses the options.</param>
    /// <param name="originalData">The signed data of a detached signature.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>One result per signature, with its revocation outcome.</returns>
    public Task<IReadOnlyList<XadesValidationResult>> ValidateAllAsync(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors = null,
        byte[]? originalData = null,
        CancellationToken cancellationToken = default) =>
        SimpleSign.Core.Diagnostics.Telemetry.MeasureValidationAsync(
            "XAdES", () => WithRevocationAsync(ValidateAll(signedXml, trustAnchors?.ToList(), originalData), cancellationToken),
            r => r.Select(x => x.Indication.ToString()));

    /// <summary>Validates every signature like <see cref="ValidateAllAsync(byte[], IEnumerable{X509Certificate2}, byte[], CancellationToken)"/>, with detached data objects by URI.</summary>
    /// <param name="signedXml">The signed XML document.</param>
    /// <param name="trustAnchors">The trust anchors; null uses the options.</param>
    /// <param name="externalData">The detached data objects, by reference URI.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>One result per signature, with its revocation outcome.</returns>
    public Task<IReadOnlyList<XadesValidationResult>> ValidateAllAsync(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors,
        IReadOnlyDictionary<string, byte[]> externalData,
        CancellationToken cancellationToken = default) =>
        SimpleSign.Core.Diagnostics.Telemetry.MeasureValidationAsync(
            "XAdES", () => WithRevocationAsync(ValidateAll(signedXml, trustAnchors?.ToList(), externalData), cancellationToken),
            r => r.Select(x => x.Indication.ToString()));

    private async Task<IReadOnlyList<XadesValidationResult>> WithRevocationAsync(
        IReadOnlyList<XadesValidationResult> results, CancellationToken cancellationToken)
    {
        if (!_options.ChecksRevocation)
        {
            return results;
        }

        var checkedResults = new List<XadesValidationResult>(results.Count);
        foreach (var result in results)
        {
            var counterSignatures = await WithRevocationAsync(result.CounterSignatures, cancellationToken).ConfigureAwait(false);
            checkedResults.Add(await WithRevocationAsync(result with { CounterSignatures = counterSignatures }, cancellationToken).ConfigureAwait(false));
        }

        return checkedResults;
    }

    private async Task<XadesValidationResult> WithRevocationAsync(XadesValidationResult result, CancellationToken cancellationToken)
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
        return result with
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
        };
    }

    private XadesValidationResult Logged(XadesValidationResult result)
    {
        if (result.Facts is { } facts && _options.ChecksRevocationFor(facts.IsChainAnchored))
        {
            result = result with { Warnings = [.. result.Warnings, RevocationStep.NotCheckedWarning] };
        }

        _logger.SignatureValidated(result.SignatureId ?? "-", result.IsValid,
            result.DetectedLevel.ToString(), result.Errors.Count, result.Warnings.Count);
        return result;
    }

    /// <summary>Validates a signed XAdES XML document against optional trust anchors. Revocation is not checked here, of the signer chain nor of the TSA chain: with <see cref="ValidationOptions.CheckRevocation"/> on, the result carries a warning saying so; use <c>ValidateAsync</c> to check it.</summary>
    public XadesValidationResult Validate(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors = null,
        byte[]? originalData = null) =>
        Logged(ValidateCore(signedXml, trustAnchors, originalData, signatureIndex: null));

    /// <summary>
    /// Validates a signed XAdES XML document whose signature references data outside the document,
    /// given by URI: the detached document and any additional external data objects.
    /// </summary>
    /// <param name="signedXml">The signed XML.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    /// <param name="externalData">The content of each external ds:Reference, keyed by its URI attribute.</param>
    public XadesValidationResult Validate(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors,
        IReadOnlyDictionary<string, byte[]> externalData)
    {
        ArgumentNullException.ThrowIfNull(externalData);
        return Logged(ValidateCore(signedXml, trustAnchors, new XadesDetachedData(null, externalData), signatureIndex: null));
    }

    /// <summary>Validates every XMLDSig signature in a signed XAdES XML document. Revocation is not checked here, of the signer chain nor of the TSA chain: with <see cref="ValidationOptions.CheckRevocation"/> on, the result carries a warning saying so; use <c>ValidateAsync</c> to check it.</summary>
    public IReadOnlyList<XadesValidationResult> ValidateAll(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors = null,
        byte[]? originalData = null) =>
        ValidateAll(signedXml, trustAnchors, (XadesDetachedData?)originalData);

    /// <summary>
    /// Validates every XMLDSig signature in a signed XAdES XML document whose signatures reference
    /// data outside the document, given by URI.
    /// </summary>
    /// <param name="signedXml">The signed XML.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    /// <param name="externalData">The content of each external ds:Reference, keyed by its URI attribute.</param>
    public IReadOnlyList<XadesValidationResult> ValidateAll(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors,
        IReadOnlyDictionary<string, byte[]> externalData)
    {
        ArgumentNullException.ThrowIfNull(externalData);
        return ValidateAll(signedXml, trustAnchors, new XadesDetachedData(null, externalData));
    }

    internal IReadOnlyList<XadesValidationResult> ValidateAll(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors,
        XadesDetachedData? originalData)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        var doc = new XmlDocument { PreserveWhitespace = true };
        try
        {
            doc.Load(new MemoryStream(signedXml));
        }
        catch (XmlException)
        {
            return [Logged(ValidateCore(signedXml, trustAnchors, originalData, signatureIndex: null))];
        }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        XmlNodeList? signatures = doc.SelectNodes(TopLevelSignatures, ns);
        if (signatures is null || signatures.Count == 0)
        {
            return [Logged(ValidateCore(signedXml, trustAnchors, originalData, signatureIndex: null))];
        }

        _logger.ValidationStarted(signatures.Count);
        var results = new List<XadesValidationResult>(signatures.Count);
        for (int index = 0; index < signatures.Count; index++)
        {
            results.Add(Logged(ValidateCore(signedXml, trustAnchors, originalData, index)));
        }

        return results;
    }

    private XadesValidationResult ValidateCore(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors,
        XadesDetachedData? originalData,
        int? signatureIndex)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        var errors = new List<string>();
        var warnings = new List<string>();

        if (signedXml.Length == 0)
        {
            errors.Add("XML data is empty.");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = AdesBaselineLevel.Basic
            };
        }

        var doc = new XmlDocument { PreserveWhitespace = true };
        try
        {
            doc.Load(new MemoryStream(signedXml));
        }
        catch (XmlException ex)
        {
            errors.Add($"XML parsing failed: {ex.Message}");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = AdesBaselineLevel.Basic
            };
        }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);

        XmlNodeList? signatures = doc.SelectNodes(TopLevelSignatures, ns);
        if (signatures is null || signatures.Count == 0)
        {
            errors.Add("No ds:Signature element found in the XML.");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = AdesBaselineLevel.Basic
            };
        }

        if (signatureIndex is null && signatures.Count != 1)
        {
            errors.Add("XML contains multiple ds:Signature elements; use ValidateAll to validate each signature.");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = AdesBaselineLevel.Basic
            };
        }

        int selectedIndex = signatureIndex ?? 0;
        if (selectedIndex < 0 || selectedIndex >= signatures.Count || signatures[selectedIndex] is not XmlElement sigElement)
        {
            errors.Add("The requested ds:Signature element was not found in the XML.");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = AdesBaselineLevel.Basic
            };
        }

        return ValidateSignatureElement(doc, ns, sigElement, trustAnchors, originalData, errors, warnings, countersigned: null, depth: 0);
    }

    // A countersignature can be countersigned in turn; bound the recursion.
    private const int MaxCounterSignatureDepth = 8;

    /// <summary>
    /// The signatures of the document itself. A ds:Signature inside a CounterSignature property is
    /// not one of them: it signs another signature and is validated under it.
    /// </summary>
    private const string TopLevelSignatures = "//ds:Signature[not(parent::xades:CounterSignature)]";

    /// <summary>
    /// Validates one ds:Signature element. <paramref name="countersigned"/> is the signature this
    /// one is a countersignature of, or null for a signature of the document.
    /// </summary>
    private XadesValidationResult ValidateSignatureElement(
        XmlDocument doc,
        XmlNamespaceManager ns,
        XmlElement sigElement,
        IEnumerable<X509Certificate2>? trustAnchors,
        XadesDetachedData? originalData,
        List<string> errors,
        List<string> warnings,
        XmlElement? countersigned,
        int depth)
    {
        // Extract XAdES properties from the signature
        var extraction = XadesPropertyExtraction(sigElement, ns, warnings);

        // Verify XMLDSig: workaround for XmlDsigEnvelopedSignatureTransform no-op in .NET 10
        // The enveloped transform should remove Signature elements from the node set
        // but doesn't in current .NET. At signing time, tempSig was in the document.
        // We rebuild the signing-time document structure for CheckSignature to work.
        // The references (HASH_FAILURE when one does not match) and the SignatureValue (SIG_CRYPTO_FAILURE) apart.
        bool referencesValid = VerifyWithSignedXml(doc, sigElement, ns, errors, out bool signatureValueValid, out bool signedDataMissing, originalData);
        bool sigValid = referencesValid && signatureValueValid;

        if (!sigValid)
        {
            errors.Add("XMLDSig signature is not cryptographically valid.");
        }
        else if (countersigned is not null && !ReferencesSignatureValueOf(sigElement, countersigned, ns))
        {
            // §5.2.7.2: a countersignature shall reference the ds:SignatureValue of the signature it is embedded in.
            errors.Add("The countersignature does not sign the ds:SignatureValue of the signature it is embedded in.");
            sigValid = false;
        }

        // Validate QualifyingProperties Target matches Signature Id
        var qpTarget = sigElement.SelectSingleNode(
            "ds:Object/xades:QualifyingProperties", ns) as XmlElement;
        if (qpTarget is not null)
        {
            string target = qpTarget.GetAttribute("Target");
            string sigId = "#" + sigElement.GetAttribute("Id");
            if (target != sigId)
            {
                warnings.Add(
                    $"QualifyingProperties Target '{target}' does not match Signature Id '{sigId}'.");
            }
        }

        // Validate SignedProperties reference has correct Type attribute
        var signedInfoRefs = sigElement.SelectNodes(
            "ds:SignedInfo/ds:Reference[@Type]", ns);
        if (signedInfoRefs is not null)
        {
            bool foundSignedPropsType = false;
            foreach (XmlElement refEl in signedInfoRefs)
            {
                if (refEl.GetAttribute("Type") == XadesUris.SignedPropertiesType)
                {
                    foundSignedPropsType = true;
                    break;
                }
            }
            if (!foundSignedPropsType)
            {
                warnings.Add(
                    "No Reference with Type='http://uri.etsi.org/01903#SignedProperties' found.");
            }
        }

        // Fall back to manual cert extraction if not found via XAdES properties
        var signerCert = extraction.SignerCert ?? ExtractSignerCert(sigElement, ns, warnings);

        if (!extraction.HasSignedProperties)
        {
            warnings.Add("No XAdES SignedProperties found; signature may be plain XMLDSig.");
        }

        AdesBaselineLevel detectedLevel = AdesBaselineLevel.Basic;
        if (extraction.HasArchiveTimeStamp)
        {
            detectedLevel = AdesBaselineLevel.Archive;
        }
        else if (extraction.HasCertificateValues || extraction.HasRevocationValues)
        {
            detectedLevel = AdesBaselineLevel.LongTerm;
        }
        else if (extraction.HasSignatureTimeStamp)
        {
            detectedLevel = AdesBaselineLevel.Timestamped;
        }

        // Timestamp validation
        bool? tsValid = null;
        bool? tsaTrusted = null;
        DateTimeOffset? provenTime = null;
        DateTimeOffset? signatureTimestampTime = null;
        if (extraction.HasSignatureTimeStamp && _options.ValidatesTimestamps)
        {
            TimestampTokenValidationResult timestamp = TimedTrust.TrustTsaAtGenTime(
                ValidateSignatureTimeStamp(sigElement, ns, extraction.SigningTime, trustAnchors, warnings),
                SignatureTimeStampToken(sigElement, ns), _options, warnings);
            tsValid = timestamp.IsIntegrityValid;
            tsaTrusted = timestamp.IsTsaTrusted;
            provenTime = timestamp is { IsIntegrityValid: true, IsTsaTrusted: true } ? timestamp.GenTime : null;
            signatureTimestampTime = timestamp.GenTime;
        }

        // AllDataObjectsTimeStamp: a signed property whose token covers the signed data objects
        (bool? dataTsValid, DateTimeOffset? dataTsTime) = ValidateDataObjectsTimeStamp(doc, sigElement, ns, originalData, errors);

        // LTV data validation (CertificateValues + RevocationValues)
        bool? ltvValid = null;
        if ((extraction.HasCertificateValues || extraction.HasRevocationValues) && _options.ValidatesLongTermData)
        {
            ltvValid = ValidateLtvData(sigElement, ns, signerCert, extraction.SigningTime, warnings);
        }

        // Archive timestamp validation
        bool? archiveTsValid = null;
        if (extraction.HasArchiveTimeStamp && _options.ValidatesArchivalData)
        {
            archiveTsValid = ValidateArchiveTimeStamp(
                sigElement, ns, originalData, warnings);
        }

        // Past signature validation (EN 319 102-1 §5.6): a trusted archive time-stamp proves the signature time-stamp
        // existed while its TSA's certificate was valid.
        if (tsValid == true && tsaTrusted != true && archiveTsValid == true && ArchiveTimeStampToken(sigElement, ns) is { } archiveToken
            && TimedTrust.TrustTsaAtLaterProof(signatureTimestampTime, SignatureTimeStampToken(sigElement, ns), archiveToken,
                trustAnchors ?? _options.TrustedRoots, _options, warnings))
        {
            tsaTrusted = true;
            provenTime = signatureTimestampTime;
        }

        // Certificate chain validation
        int chainErrorsStart = errors.Count;
        bool chainValid = ValidateCertificateChain(signerCert, trustAnchors, sigElement, ns, errors, out bool chainAnchored);

        // Not anchored today: the anchors of the proof of existence (a trusted-list service withdrawn since).
        if (!chainAnchored && provenTime is { } proven && TimedTrust.IsConfigured(_options))
        {
            var timedErrors = new List<string>();
            bool timedValid = ValidateCertificateChain(
                signerCert, [.. trustAnchors ?? [], .. TimedTrust.AnchorsAt(_options, proven)], sigElement, ns, timedErrors, out bool timedAnchored);
            if (timedAnchored)
            {
                errors.RemoveRange(chainErrorsStart, errors.Count - chainErrorsStart);
                errors.AddRange(timedErrors);
                warnings.Add(TimedTrust.SignerWarning(proven));
                (chainValid, chainAnchored) = (timedValid, true);
            }
        }
        var (claimedRoles, attributeCertificates, signedAssertions) = ReadSignerRoles(sigElement, ns, warnings);
        var facts = new ValidationFacts
        {
            IsIntegrityValid = referencesValid,
            // A reference whose data was not given (a detached signature validated alone): SIGNED_DATA_NOT_FOUND, and
            // the signature is judged by its SignatureValue over SignedInfo alone.
            IsSignatureValid = signedDataMissing ? signatureValueValid : sigValid,
            SignedDataFound = signedDataMissing ? false : null,
            SignerCertificate = signerCert,
            IsCertificateChainValid = chainValid,
            IsTsaTrusted = tsaTrusted,
            DigestAlgorithmOid = SignatureMethodDigestOid(sigElement, ns),
            ProofOfExistence = provenTime,
            ChainReachesAnchor = chainAnchored,
            Chain = signerCert is null ? null : SignerAcceptance.OrderChain(
                signerCert, [.. KeyInfoCertificates(sigElement, ns), .. trustAnchors ?? [], .. _options.TrustedRoots ?? []]),
            ClaimedSigningTime = extraction.SigningTime,
            SigningTimeKnown = true,
            HasSigningCertificateReference = sigElement.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificateV2"
                + " | ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate", ns) is not null,
            SignaturePolicyOid = ReadSignaturePolicy(sigElement, ns)?.Oid,
            SignaturePolicyKnown = true,
            SignedAttributes = XadesSignedAttributeFacts.Read(sigElement, ns, claimedRoles, attributeCertificates.Count),
            UnsignedAttributes = XadesUnsigned(sigElement, ns, extraction.HasSignatureTimeStamp, extraction.HasArchiveTimeStamp, tsValid, archiveTsValid),
            SignatureFormat = (extraction.HasSignedProperties ? "XAdES-BASELINE-" : "XML-NOT-ETSI-") + detectedLevel switch
            {
                AdesBaselineLevel.Archive => "LTA",
                AdesBaselineLevel.LongTerm => "LT",
                AdesBaselineLevel.Timestamped => "T",
                _ => "B",
            },
            SignatureIdUnique = string.IsNullOrEmpty(extraction.SignatureId) ? null : CountIds(doc, extraction.SignatureId) == 1,
            CoversWholeDocument = sigElement.SelectSingleNode("ds:SignedInfo/ds:Reference[@URI='']", ns) is not null ? true : null,
            PolicyStorePresent = ReadSignaturePolicy(sigElement, ns) is null ? null : XadesSignatureBuilder.ReadSignaturePolicyStore(sigElement, ns) is not null,
            // Obtained when the signature carries it (SignaturePolicyStore) or a provider found it; otherwise not.
            PolicyDocumentAvailable = ReadSignaturePolicy(sigElement, ns)?.Oid is not { } policyOid ? null
                : XadesSignatureBuilder.ReadSignaturePolicyStore(sigElement, ns) is not null || _options.PolicyDocumentFound(policyOid) == true,
            IsCounterSignature = depth > 0,
            StructureErrors = Internal.XmlSchemas.Validate(sigElement),
            TrustedLists = _options.TrustedLists,
            EmbeddedCrls = _options.ValidatesLongTermData ? EmbeddedValues(sigElement, ns, "CRLValues", "EncapsulatedCRLValue") : null,
            EmbeddedOcsps = _options.ValidatesLongTermData ? EmbeddedValues(sigElement, ns, "OCSPValues", "EncapsulatedOCSPValue") : null,
            Timestamps = XadesTimestampTokens(sigElement, ns, tsValid, tsaTrusted, archiveTsValid, trustAnchors, dataTsValid),
        };
        var evaluation = ValidationPolicyEvaluator.Evaluate(facts, _options.PolicyFor(facts.SignaturePolicyOid));
        warnings.AddRange(evaluation.Warnings);

        return new XadesValidationResult
        {
            Indication = evaluation.Indication,
            SubIndication = evaluation.SubIndication,
            Constraints = evaluation.Constraints,
            ValidationObjects = evaluation.ValidationObjects,
            AppliedPolicy = evaluation.Policy,
            BestSignatureTime = evaluation.BestSignatureTime,
            Facts = facts,
            ChainCandidates = [.. KeyInfoCertificates(sigElement, ns), .. trustAnchors ?? [], .. _options.TrustedRoots ?? []],
            EmbeddedCrls = _options.ValidatesLongTermData ? EmbeddedValues(sigElement, ns, "CRLValues", "EncapsulatedCRLValue") : [],
            EmbeddedOcsps = _options.ValidatesLongTermData ? EmbeddedValues(sigElement, ns, "OCSPValues", "EncapsulatedOCSPValue") : [],
            SignatureTimestampToken = SignatureTimeStampToken(sigElement, ns),
            SignatureId = extraction.SignatureId,
            IsSignatureValid = sigValid,
            IsIntegrityValid = referencesValid,
            IsCertificateChainValid = chainValid,
            HasValidSignatureTimeStamp = tsValid,
            HasValidDataObjectsTimeStamp = dataTsValid,
            DataObjectsTimeStampTime = dataTsTime,
            IsTsaTrusted = tsaTrusted,
            IsLtvDataValid = ltvValid,
            HasValidArchiveTimeStamp = archiveTsValid,
            SignerCertificate = signerCert,
            SigningTime = extraction.SigningTime,
            SignaturePolicy = ReadSignaturePolicy(sigElement, ns),
            SignaturePolicyStore = XadesSignatureBuilder.ReadSignaturePolicyStore(sigElement, ns),
            HasValidCompleteReferences = ValidateCompleteReferences(sigElement, ns, warnings),
            HasValidSigAndRefsTimeStamp = ValidateSigAndRefsTimeStamp(sigElement, ns, warnings),
            DetectedLevel = detectedLevel,
            ClaimedRoles = claimedRoles,
            AttributeCertificates = attributeCertificates,
            SignedAssertions = signedAssertions,
            CounterSignatures = ValidateCounterSignatures(doc, ns, sigElement, trustAnchors, originalData, depth),
            Errors = errors,
            Warnings = warnings
        };
    }

    /// <summary>The unsigned properties of a signature in the terms of the UnsignedAttributes constraints.</summary>
    private static UnsignedAttributeFacts XadesUnsigned(XmlElement sigElement, XmlNamespaceManager ns, bool signatureTimeStamp, bool archiveTimeStamp, bool? tsValid, bool? archiveValid)
    {
        const string Unsigned = "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/";
        return new UnsignedAttributeFacts
        {
            CounterSignature = sigElement.SelectSingleNode(Unsigned + "xades:CounterSignature", ns) is not null,
            SignatureTimeStamp = signatureTimeStamp,
            ValidationDataTimeStamp = sigElement.SelectSingleNode(Unsigned + "xades:SigAndRefsTimeStamp | " + Unsigned + "xades141:SigAndRefsTimeStampV2", ns) is not null,
            ValidationDataRefsOnlyTimeStamp = sigElement.SelectSingleNode(Unsigned + "xades:RefsOnlyTimeStamp | " + Unsigned + "xades141:RefsOnlyTimeStampV2", ns) is not null,
            ArchiveTimeStamp = archiveTimeStamp,
            TLevelTimeStampValid = signatureTimeStamp ? tsValid : false,
            LtaLevelTimeStampValid = archiveTimeStamp ? archiveValid : false,
        };
    }

    /// <summary>The signature and archive timestamps of a signature, for the Timestamp context of the policy.</summary>
    private IReadOnlyList<TimestampTokenFacts>? XadesTimestampTokens(
        XmlElement sigElement, XmlNamespaceManager ns, bool? tsValid, bool? tsaTrusted, bool? archiveValid, IEnumerable<X509Certificate2>? trustAnchors,
        bool? contentValid)
    {
        var tokens = new List<TimestampTokenFacts>();
        if (contentValid is not null && sigElement.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:AllDataObjectsTimeStamp/xades:EncapsulatedTimeStamp",
                ns) is { } content)
        {
            try
            {
                byte[] contentToken = Convert.FromBase64String(content.InnerText.Trim());
                tokens.Add(new TimestampTokenFacts(TimestampTokenKind.Content, contentToken, contentValid,
                    TimedTrust.TokenChains(contentToken, trustAnchors ?? _options.TrustedRoots, _options)));
            }
            catch (FormatException)
            {
                // Reported by the data objects timestamp validation.
            }
        }

        if (tsValid is not null && SignatureTimeStampToken(sigElement, ns) is { } signatureToken)
        {
            tokens.Add(new TimestampTokenFacts(TimestampTokenKind.Signature, signatureToken, tsValid, tsaTrusted));
        }

        // An unreadable archive timestamp is reported by its own validation.
        if (archiveValid is not null && ArchiveTimeStampToken(sigElement, ns) is { } archiveToken
            && TimedTrust.TokenChains(archiveToken, trustAnchors ?? _options.TrustedRoots, _options) is { } trusted)
        {
            tokens.Add(new TimestampTokenFacts(TimestampTokenKind.Archive, archiveToken, archiveValid, trusted));
        }

        return tokens.Count == 0 ? null : tokens;
    }

    /// <summary>The token of the (first) archive time-stamp, or null when there is none or it is not base64.</summary>
    private static byte[]? ArchiveTimeStampToken(XmlElement sigElement, XmlNamespaceManager ns)
    {
        const string Unsigned = "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/";
        if (sigElement.SelectSingleNode(Unsigned + "xades141:ArchiveTimeStamp/xades:EncapsulatedTimeStamp | " + Unsigned + "xades141:ArchiveTimeStamp/xades141:EncapsulatedTimeStamp | "
            + Unsigned + "xades:ArchiveTimeStamp/xades:EncapsulatedTimeStamp", ns) is not { } encapsulated)
        {
            return null;
        }

        try
        {
            return Convert.FromBase64String(encapsulated.InnerText.Trim());
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>How many elements of the document have the Id <paramref name="id"/>.</summary>
    private static int CountIds(XmlDocument doc, string id) =>
        doc.SelectNodes("//*[@Id]")?.OfType<XmlElement>().Count(e => e.GetAttribute("Id") == id) ?? 0;

    /// <summary>The OID of the digest of the SignedInfo's SignatureMethod (RSA, ECDSA), or null when it has none of its own (RSA-PSS).</summary>
    private static string? SignatureMethodDigestOid(XmlElement sigElement, XmlNamespaceManager ns)
    {
        string? uri = (sigElement.SelectSingleNode("ds:SignedInfo/ds:SignatureMethod", ns) as XmlElement)?.GetAttribute("Algorithm");
        if (string.IsNullOrEmpty(uri) || uri.Contains("MGF1", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return uri.EndsWith("sha1", StringComparison.OrdinalIgnoreCase) ? "1.3.14.3.2.26"
            : uri.EndsWith("sha224", StringComparison.OrdinalIgnoreCase) ? "2.16.840.1.101.3.4.2.4"
            : uri.EndsWith("sha3-256", StringComparison.OrdinalIgnoreCase) ? "2.16.840.1.101.3.4.2.8"
            : uri.EndsWith("sha3-384", StringComparison.OrdinalIgnoreCase) ? "2.16.840.1.101.3.4.2.9"
            : uri.EndsWith("sha3-512", StringComparison.OrdinalIgnoreCase) ? "2.16.840.1.101.3.4.2.10"
            : uri.EndsWith("sha256", StringComparison.OrdinalIgnoreCase) ? "2.16.840.1.101.3.4.2.1"
            : uri.EndsWith("sha384", StringComparison.OrdinalIgnoreCase) ? "2.16.840.1.101.3.4.2.2"
            : uri.EndsWith("sha512", StringComparison.OrdinalIgnoreCase) ? "2.16.840.1.101.3.4.2.3"
            : uri.EndsWith("md5", StringComparison.OrdinalIgnoreCase) ? "1.2.840.113549.2.5"
            : null;
    }

    /// <summary>Validates the countersignatures in the CounterSignature unsigned properties of a signature.</summary>
    private List<XadesValidationResult> ValidateCounterSignatures(
        XmlDocument doc,
        XmlNamespaceManager ns,
        XmlElement sigElement,
        IEnumerable<X509Certificate2>? trustAnchors,
        XadesDetachedData? originalData,
        int depth)
    {
        var results = new List<XadesValidationResult>();
        XmlNodeList? counterSignatures = sigElement.SelectNodes(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CounterSignature/ds:Signature", ns);
        if (counterSignatures is null || depth >= MaxCounterSignatureDepth)
        {
            return results;
        }

        foreach (XmlElement counterSignature in counterSignatures)
        {
            results.Add(Logged(ValidateSignatureElement(
                doc, ns, counterSignature, trustAnchors, originalData, [], [], countersigned: sigElement, depth + 1)));
        }

        return results;
    }

    /// <summary>Whether a ds:Reference of <paramref name="counterSignature"/> points to the ds:SignatureValue of <paramref name="countersigned"/>.</summary>
    private static bool ReferencesSignatureValueOf(XmlElement counterSignature, XmlElement countersigned, XmlNamespaceManager ns)
    {
        string valueId = (countersigned.SelectSingleNode("ds:SignatureValue", ns) as XmlElement)?.GetAttribute("Id") ?? string.Empty;
        if (valueId.Length == 0)
        {
            return false;
        }

        foreach (XmlElement reference in counterSignature.SelectNodes("ds:SignedInfo/ds:Reference", ns)!)
        {
            if (reference.GetAttribute("URI") == "#" + valueId)
            {
                return true;
            }
        }

        return false;
    }

    private bool ValidateCertificateChain(
        X509Certificate2? signerCert,
        IEnumerable<X509Certificate2>? trustAnchors,
        XmlElement sigElement,
        XmlNamespaceManager ns,
        List<string> errors,
        out bool reachesAnchor)
    {
        reachesAnchor = false;
        if (signerCert is null)
        {
            errors.Add("No signer certificate found in the signature.");
            return false;
        }

        // Intermediates come from KeyInfo/X509Data, as for the TSA chain.
        var embedded = KeyInfoCertificates(sigElement, ns);
        try
        {
            using var chain = new X509Chain { ChainPolicy = { TrustMode = X509ChainTrustMode.System } };
            CryptoUtility.ConfigureChainPolicy(chain, _options.ChecksRevocation);
            chain.ChainPolicy.DisableCertificateDownloads = !_options.Verifier.UseAia;
            foreach (var certificate in embedded)
            {
                chain.ChainPolicy.ExtraStore.Add(certificate);
            }

            // Same trust rules as CadesSignatureValidator: explicit anchors or ValidationOptions.TrustedRoots
            // (or TrustSystemRoots = false) switch to custom root trust.
            bool hasCustomRoots = trustAnchors is not null
                || _options.TrustedRoots is { Count: > 0 }
                || !_options.TrustSystemRoots;
            if (hasCustomRoots)
            {
                foreach (var anchor in (trustAnchors ?? []).Concat(_options.TrustedRoots ?? []))
                {
                    chain.ChainPolicy.CustomTrustStore.Add(anchor);
                }

                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationFlags =
                    X509VerificationFlags.IgnoreEndRevocationUnknown |
                    X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
            }

            bool chainValid = chain.Build(signerCert);
            reachesAnchor = CryptoUtility.ReachesTrustAnchor(chain, chainValid);
            if (!chainValid)
            {
                foreach (var status in chain.ChainStatus)
                {
                    errors.Add($"Certificate chain error: {status.Status} \u2014 {status.StatusInformation}");
                }
            }

            return chainValid;
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            errors.Add($"Certificate chain validation threw: {ex.Message}");
            return false;
        }
        finally
        {
            foreach (var certificate in embedded)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>Every certificate in KeyInfo/X509Data (signer and chain); unreadable entries are skipped.</summary>
    private static List<X509Certificate2> KeyInfoCertificates(XmlElement sigElement, XmlNamespaceManager ns)
    {
        var certificates = new List<X509Certificate2>();
        if (sigElement.SelectNodes("ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns) is not { } nodes)
        {
            return certificates;
        }

        foreach (XmlNode node in nodes)
        {
            try
            {
                certificates.Add(CertificateLoader.LoadCertificate(DecodeBase64(node)));
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException)
            {
                // A malformed extra certificate only means the chain may not be built.
            }
        }

        return certificates;
    }

    /// <summary>
    /// Verifies the references of SignedInfo (returned) and the SignatureValue over SignedInfo
    /// (<paramref name="signatureValueValid"/>). A structural problem fails both.
    /// </summary>
    private static bool VerifyWithSignedXml(
        XmlDocument doc,
        XmlElement sigElement,
        XmlNamespaceManager ns,
        List<string> errors,
        out bool signatureValueValid,
        out bool signedDataMissing,
        XadesDetachedData? originalData = null)
    {
        signatureValueValid = false;
        signedDataMissing = false;
        try
        {
            if (sigElement.SelectSingleNode("ds:SignedInfo", ns) is not XmlElement signedInfoEl)
            {
                errors.Add("Missing SignedInfo element.");
                return false;
            }

            if (sigElement.SelectSingleNode("ds:SignatureValue", ns) is not XmlElement signatureValueEl)
            {
                errors.Add("Missing SignatureValue element.");
                return false;
            }

            var keyInfoEl = sigElement.SelectSingleNode("ds:KeyInfo", ns) as XmlElement;

            // Step 1: Verify signature value (cryptographic integrity)
            // The XmlDsigEnvelopedSignatureTransform is a no-op in .NET 10,
            // so SignedXml.CheckSignature() would compute the document digest
            // over the full current document (including realSig).
            // At signing time, the document had tempSig (different content).
            // We verify signature value and digest values separately.

            // Determine hash algorithm from SignatureMethod
            if (signedInfoEl.SelectSingleNode("ds:SignatureMethod", ns) is not XmlElement sigMethodEl)
            {
                errors.Add("No SignatureMethod element found.");
                return false;
            }

            string sigMethodUri = sigMethodEl.GetAttribute("Algorithm");
            HashAlgorithmName sigHashAlg = GetHashAlgorithmFromSignatureMethod(sigMethodUri);
            if (sigHashAlg.Name is null)
            {
                errors.Add($"Unsupported signature method: {sigMethodUri}");
                return false;
            }

            // Canonicalize SignedInfo with the algorithm it declares (XMLDSig Core 1.1 §4.4.1).
            // An algorithm the BCL does not implement (Canonical XML 1.1) keeps the exclusive
            // form this validator has always applied: the signature value then decides.
            string signedInfoCanonicalization =
                (signedInfoEl.SelectSingleNode("ds:CanonicalizationMethod", ns) as XmlElement)?.GetAttribute("Algorithm") ?? string.Empty;
            if (signedInfoCanonicalization is not (XmlDSigUrls.ExcC14N or XmlDSigUrls.ExcC14NWithComments
                or XmlDSigUrls.C14N or XmlDSigUrls.C14NWithComments))
            {
                signedInfoCanonicalization = XmlDSigUrls.ExcC14N;
            }

            byte[] signedInfoBytes = XadesSignatureBuilder.CanonicalizeElement(signedInfoEl, signedInfoCanonicalization);
            byte[] signedInfoHash = CryptoUtility.ComputeHash(signedInfoBytes, sigHashAlg);

            // Get signature value
            byte[] signatureValue = DecodeBase64(signatureValueEl);

            // Get the signer certificate
            if (keyInfoEl?.SelectSingleNode(
                "ds:X509Data/ds:X509Certificate", ns) is not XmlElement certEl)
            {
                errors.Add("No X509Certificate found in KeyInfo.");
                return false;
            }

            byte[] rawCert;
            try
            {
                rawCert = DecodeBase64(certEl);
            }
            // S2221: intentional -- validation pipeline converts exceptions to error messages
            catch (Exception ex)
            {
                errors.Add($"Failed to parse certificate: {ex.Message}");
                return false;
            }

#pragma warning disable SYSLIB0057
            using X509Certificate2 signerCert = new(rawCert);
#pragma warning restore SYSLIB0057

            // Verify the signature value
            bool isRsaPss = sigMethodUri == XmlDSigUrls.RsaPssSha256
                || sigMethodUri == XmlDSigUrls.RsaPssSha384
                || sigMethodUri == XmlDSigUrls.RsaPssSha512;

            using RSA? rsa = signerCert.GetRSAPublicKey();
            if (rsa is not null)
            {
                var padding = isRsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                signatureValueValid = rsa.VerifyHash(signedInfoHash, signatureValue, sigHashAlg, padding);
            }
            else
            {
                using ECDsa? ecdsa = signerCert.GetECDsaPublicKey();
                signatureValueValid = ecdsa is not null && ecdsa.VerifyHash(signedInfoHash, signatureValue);
            }

            // Step 2: Verify reference digests, whatever the signature value gave.
            return VerifyReferenceDigests(doc, sigElement, signedInfoEl, ns, errors, out signedDataMissing, originalData);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            errors.Add($"XMLDSig verification threw: {ex.Message}");
            return false;
        }
    }

    private static bool VerifyReferenceDigests(
        XmlDocument doc,
        XmlElement sigElement,
        XmlElement signedInfoEl,
        XmlNamespaceManager ns,
        List<string> errors,
        out bool dataMissing,
        XadesDetachedData? originalData = null)
    {
        bool allValid = true;
        dataMissing = false;
        var refNodes = signedInfoEl.SelectNodes("ds:Reference", ns);

        if (refNodes is null || refNodes.Count == 0)
        {
            errors.Add("No ds:Reference elements found in SignedInfo.");
            return false;
        }

        foreach (XmlElement refEl in refNodes)
        {
            string uri = refEl.GetAttribute("URI") ?? string.Empty;

            var digestMethodEl = refEl.SelectSingleNode("ds:DigestMethod", ns);
            var digestValueEl = refEl.SelectSingleNode("ds:DigestValue", ns);

            if (digestMethodEl is not XmlElement dmEl || digestValueEl is not XmlElement dvEl)
            {
                errors.Add($"Reference URI='{uri}' is missing DigestMethod or DigestValue.");
                allValid = false;
                continue;
            }

            string digestMethodUri = dmEl.GetAttribute("Algorithm");
            HashAlgorithmName hashAlg;
            try
            {
                hashAlg = XmlDSigUrls.GetHashAlgorithmFromUri(digestMethodUri);
            }
            // S2221: intentional -- validation pipeline converts exceptions to error messages
            catch (Exception ex)
            {
                errors.Add($"Unsupported digest method '{digestMethodUri}' in reference URI='{uri}': {ex.Message}");
                allValid = false;
                continue;
            }

            string expectedDigestBase64 = dvEl.InnerText.Trim();
            byte[] expectedDigest;
            try
            {
                expectedDigest = Convert.FromBase64String(expectedDigestBase64);
            }
            // S2221: intentional -- validation pipeline converts exceptions to error messages
            catch (Exception ex)
            {
                errors.Add($"Invalid DigestValue in reference URI='{uri}': {ex.Message}");
                allValid = false;
                continue;
            }

            byte[] actualDigest;
            try
            {
                actualDigest = ComputeReferenceDigest(doc, sigElement, refEl, hashAlg, ns, originalData);
            }
            catch (ReferenceDataNotFoundException ex)
            {
                errors.Add(ex.Message);
                allValid = false;
                dataMissing = true;
                continue;
            }
            // S2221: intentional -- validation pipeline converts exceptions to error messages
            catch (Exception ex)
            {
                errors.Add($"Failed to compute digest for '{uri}': {ex.Message}");
                allValid = false;
                continue;
            }

            if (!expectedDigest.AsSpan().SequenceEqual(actualDigest))
            {
                errors.Add($"Digest mismatch for reference URI='{uri}'.");
                allValid = false;
            }
        }

        return allValid;
    }

    private static byte[] ComputeReferenceDigest(
        XmlDocument doc,
        XmlElement sigElement,
        XmlElement refEl,
        HashAlgorithmName hashAlg,
        XmlNamespaceManager ns,
        XadesDetachedData? originalData = null) =>
        CryptoUtility.ComputeHash(ComputeReferenceOctets(doc, sigElement, refEl, ns, originalData), hashAlg);

    /// <summary>
    /// The octets a ds:Reference digests: the referenced data after its transforms
    /// (XMLDSig Core 1.1 §4.4.3.2). Time-stamps on data objects cover the same octets.
    /// </summary>
    private static byte[] ComputeReferenceOctets(
        XmlDocument doc,
        XmlElement sigElement,
        XmlElement refEl,
        XmlNamespaceManager ns,
        XadesDetachedData? originalData = null)
    {
        string uri = refEl.GetAttribute("URI") ?? string.Empty;

        if (string.IsNullOrEmpty(uri))
        {
            bool hasEnvelopedTransform = HasEnvelopedTransform(refEl, ns);
            return ComputeDocumentOctetsWithTempSig(
                doc, hasEnvelopedTransform,
                GetReferenceCanonicalizationAlgorithm(refEl, ns));
        }

        if (uri.StartsWith('#'))
        {
            string id = uri[1..];
            return ComputeFragmentOctets(doc, id, refEl, ns);
        }

        if (originalData?.Resolve(uri) is { Length: > 0 } externalData)
        {
            return XmlCompatibleData(externalData, refEl, ns);
        }

        throw new ReferenceDataNotFoundException(
            $"The data of reference '{uri}' was not given: pass it (the detached data) to validate a detached signature.");
    }

    private static byte[] XmlCompatibleData(
        byte[] data,
        XmlElement refEl,
        XmlNamespaceManager ns)
    {
        string? canonicalizationAlgorithm = GetReferenceCanonicalizationAlgorithm(refEl, ns);
        if (canonicalizationAlgorithm is not null)
        {
            var dataDoc = new XmlDocument { PreserveWhitespace = true };
            dataDoc.Load(new MemoryStream(data));
            return XadesSignatureBuilder.CanonicalizeXml(dataDoc, canonicalizationAlgorithm);
        }

        return data;
    }

    /// <summary>
    /// Checks AllDataObjectsTimeStamp (ETSI EN 319 132-1 §5.2.8.1): the token must be intact and its
    /// message imprint must be the hash of the octets of every ds:Reference of SignedInfo, in order,
    /// except the one to SignedProperties. Returns null when the signature has no such property.
    /// </summary>
    private static (bool? Valid, DateTimeOffset? Time) ValidateDataObjectsTimeStamp(
        XmlDocument doc, XmlElement sigElement, XmlNamespaceManager ns, XadesDetachedData? originalData, List<string> errors)
    {
        if (sigElement.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:AllDataObjectsTimeStamp",
                ns) is not XmlElement timestamp)
        {
            return (null, null);
        }

        try
        {
            if (timestamp.SelectSingleNode("xades:EncapsulatedTimeStamp", ns) is not XmlElement encapsulated)
            {
                errors.Add("AllDataObjectsTimeStamp has no EncapsulatedTimeStamp.");
                return (false, null);
            }

            using var input = new MemoryStream();
            foreach (XmlElement reference in sigElement.SelectNodes("ds:SignedInfo/ds:Reference", ns)!)
            {
                if (reference.GetAttribute("Type") != XadesUris.SignedPropertiesType)
                {
                    input.Write(ComputeReferenceOctets(doc, sigElement, reference, ns, originalData));
                }
            }

            var verification = TimestampToken.Verify(DecodeBase64(encapsulated), input.ToArray());
            if (verification.IsImprintValid && verification.IsIntegrityValid)
            {
                return (true, verification.Info?.GenerationTime);
            }

            errors.Add(verification.IsImprintValid
                ? "AllDataObjectsTimeStamp is not an intact timestamp token."
                : "AllDataObjectsTimeStamp does not cover the signed data objects.");
            return (false, null);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            errors.Add($"AllDataObjectsTimeStamp could not be validated: {ex.Message}");
            return (false, null);
        }
    }

    private static bool HasEnvelopedTransform(XmlElement refEl, XmlNamespaceManager ns)
    {
        var transforms = refEl.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null)
        {
            return false;
        }

        foreach (XmlElement t in transforms)
        {
            string algorithm = t.GetAttribute("Algorithm");
            if (algorithm == XmlDSigUrls.EnvelopedSignatureTransform
                || algorithm == XmlDSigUrls.XPathTransform)
            {
                return true;
            }
        }

        return false;
    }

    private static string? GetReferenceCanonicalizationAlgorithm(XmlElement refEl, XmlNamespaceManager ns)
    {
        XmlNodeList? transforms = refEl.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null)
        {
            return null;
        }

        foreach (XmlElement transform in transforms)
        {
            string algorithm = transform.GetAttribute("Algorithm");
            if (algorithm is XmlDSigUrls.ExcC14N or XmlDSigUrls.ExcC14NWithComments or
                XmlDSigUrls.C14N or XmlDSigUrls.C14NWithComments)
            {
                return algorithm;
            }
        }

        return null;
    }

    private static byte[] ComputeDocumentOctetsWithTempSig(
        XmlDocument doc,
        bool hasEnvelopedTransform,
        string? canonicalizationAlgorithm)
    {
        // XmlDsigEnvelopedSignatureTransform is broken in .NET 10 (it does not
        // remove <Signature> elements).  The signing code now computes the
        // document digest by removing ALL <Signature> elements before
        // canonicalizing.  Match that here.
        var clone = (XmlDocument)doc.CloneNode(true);
        var cloneNs = new XmlNamespaceManager(clone.NameTable);
        cloneNs.AddNamespace("ds", XmlDSigUrls.DsNamespace);

        // Only remove Signature elements if the reference had an
        // EnvelopedSignatureTransform.
        if (hasEnvelopedTransform)
        {
            var signatures = clone.SelectNodes("//ds:Signature", cloneNs);
            if (signatures is not null)
            {
                for (int i = signatures.Count - 1; i >= 0; i--)
                {
                    var sig = signatures[i]!;
                    sig.ParentNode!.RemoveChild(sig);
                }
            }
        }

        return XadesSignatureBuilder.CanonicalizeXml(clone, canonicalizationAlgorithm ?? XmlDSigUrls.ExcC14N);
    }

    private static byte[] ComputeFragmentOctets(
        XmlDocument doc,
        string id,
        XmlElement reference,
        XmlNamespaceManager ns)
    {
        // Find element by Id — for SignedProperties, this is inside
        // ds:Object → xades:QualifyingProperties → xades:SignedProperties.
        // Use a broad XPath to find any element with the matching Id.
        if (doc.SelectSingleNode($"//*[@Id='{id}']") is not XmlElement element)
        {
            throw new InvalidOperationException($"Element with Id='{id}' not found.");
        }

        if (reference.SelectSingleNode(
                $"ds:Transforms/ds:Transform[@Algorithm='{XmlDSigUrls.Base64Transform}']", ns) is not null)
        {
            return DecodeBase64(element);
        }

        // Canonicalize the element as a document subset. A reference without a canonicalization
        // transform keeps the exclusive default this validator has always used.
        return XadesSignatureBuilder.CanonicalizeElement(
            element, GetReferenceCanonicalizationAlgorithm(reference, ns) ?? XmlDSigUrls.ExcC14N);
    }

    private static XadesPropertyExtractionResult XadesPropertyExtraction(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        List<string> warnings)
    {
        string signatureId = sigElement.GetAttribute("Id");
        bool hasSignedProperties = false;
        bool hasSignatureTimeStamp = false;
        bool hasCertificateValues = false;
        bool hasRevocationValues = false;
        bool hasArchiveTimeStamp = false;
        DateTimeOffset? signingTime = null;
        X509Certificate2? signerCert = null;

        if (sigElement.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) is XmlElement qualifyingProps)
        {
            if (qualifyingProps.SelectSingleNode(
                    "xades:SignedProperties", ns) is XmlElement signedProps)
            {
                hasSignedProperties = true;

                var st = signedProps.SelectSingleNode(
                    "xades:SignedSignatureProperties/xades:SigningTime", ns);
                if (st is not null && DateTimeOffset.TryParse(st.InnerText, out var parsedSt))
                {
                    signingTime = parsedSt;
                }

                var signingCert = signedProps.SelectSingleNode(
                    "xades:SignedSignatureProperties/xades:SigningCertificateV2 | xades:SignedSignatureProperties/xades:SigningCertificate", ns);

                if (signingCert is not null && signerCert is null)
                {
                    var certDigest = signingCert.SelectSingleNode(
                        "xades:Cert/xades:CertDigest/ds:DigestValue", ns);
                    if (certDigest is not null)
                    {
                        var hashAlg = DetectHashAlgorithm(
                            (XmlElement?)signingCert.SelectSingleNode(
                                "xades:Cert/xades:CertDigest/ds:DigestMethod", ns));
                        var expectedHash = DecodeBase64(certDigest);

                        var certNodes = sigElement.SelectNodes(
                            "ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns);
                        if (certNodes is not null)
                        {
                            foreach (XmlElement certEl in certNodes)
                            {
                                var rawCert = DecodeBase64(certEl);
                                var computedHash = CryptoUtility.ComputeHash(rawCert, hashAlg);
                                if (computedHash.AsSpan().SequenceEqual(expectedHash))
                                {
                                    try
                                    {
                                        signerCert = CertificateLoader.LoadCertificate(rawCert);
                                    }
                                    // S2221: intentional -- validation pipeline converts exceptions to error messages
                                    catch (Exception ex)
                                    {
                                        warnings.Add($"Failed to load certificate from {signingCert.LocalName}: {ex.Message}");
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            var unsignedProps = qualifyingProps.SelectSingleNode(
                "xades:UnsignedProperties", ns);
            if (unsignedProps is not null)
            {
                // Check both nested (UnsignedSignatureProperties) and flat (pre-standardization) structures
                var unsignedSigProps = unsignedProps.SelectSingleNode(
                    "xades:UnsignedSignatureProperties", ns);

                hasSignatureTimeStamp =
                    unsignedSigProps?.SelectSingleNode("xades:SignatureTimeStamp", ns) is not null
                    || unsignedProps.SelectSingleNode("xades:SignatureTimeStamp", ns) is not null;

                hasCertificateValues =
                    unsignedSigProps?.SelectSingleNode("xades:CertificateValues", ns) is not null
                    || unsignedProps.SelectSingleNode("xades:CertificateValues", ns) is not null;

                hasRevocationValues =
                    unsignedSigProps?.SelectSingleNode("xades:RevocationValues", ns) is not null
                    || unsignedProps.SelectSingleNode("xades:RevocationValues", ns) is not null;

                var ats = unsignedSigProps?.SelectSingleNode(
                    "xades141:ArchiveTimeStamp", ns);
                ats ??= unsignedSigProps?.SelectSingleNode(
                        "xades:ArchiveTimeStamp", ns);
                ats ??= unsignedProps.SelectSingleNode(
                    "xades141:ArchiveTimeStamp", ns) ??
                    (XmlElement?)unsignedProps.SelectSingleNode(
                        "xades:ArchiveTimeStamp", ns);

                hasArchiveTimeStamp = ats is not null;
            }
        }

        return new XadesPropertyExtractionResult(
            hasSignedProperties, hasSignatureTimeStamp, hasCertificateValues,
            hasRevocationValues, hasArchiveTimeStamp, signingTime, signerCert, signatureId);
    }

    private static X509Certificate2? ExtractSignerCert(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        List<string> warnings)
    {
        try
        {
            if (sigElement.SelectSingleNode(
                "ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns) is not XmlElement certEl)
            {
                return null;
            }

            byte[] rawCert = DecodeBase64(certEl);
            return CertificateLoader.LoadCertificate(rawCert);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            warnings.Add($"Failed to extract signer certificate from KeyInfo: {ex.Message}");
            return null;
        }
    }

    private static HashAlgorithmName GetHashAlgorithmFromSignatureMethod(string sigMethodUri)
    {
        return sigMethodUri switch
        {
            SignedXml.XmlDsigRSASHA1Url => HashAlgorithmName.SHA1,
            SignedXml.XmlDsigRSASHA256Url => HashAlgorithmName.SHA256,
            SignedXml.XmlDsigRSASHA384Url => HashAlgorithmName.SHA384,
            SignedXml.XmlDsigRSASHA512Url => HashAlgorithmName.SHA512,
            XmlDSigUrls.RsaPssSha256 => HashAlgorithmName.SHA256,
            XmlDSigUrls.RsaPssSha384 => HashAlgorithmName.SHA384,
            XmlDSigUrls.RsaPssSha512 => HashAlgorithmName.SHA512,
            XmlDSigUrls.EcdsaSha256 => HashAlgorithmName.SHA256,
            XmlDSigUrls.EcdsaSha384 => HashAlgorithmName.SHA384,
            XmlDSigUrls.EcdsaSha512 => HashAlgorithmName.SHA512,
            _ => default
        };
    }

    private const string UnsignedSignatureProperties =
        "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/";

    private static bool? ValidateCompleteReferences(XmlElement sigElement, XmlNamespaceManager ns, List<string> warnings) =>
        sigElement.SelectSingleNode(UnsignedSignatureProperties + "xades:CompleteCertificateRefs", ns) is null
            && sigElement.SelectSingleNode(UnsignedSignatureProperties + "xades:CompleteRevocationRefs", ns) is null
            ? null
            : XadesSignatureBuilder.ValidateCompleteReferences(sigElement, ns, warnings);

    private static bool? ValidateSigAndRefsTimeStamp(XmlElement sigElement, XmlNamespaceManager ns, List<string> warnings)
    {
        if (sigElement.SelectSingleNode(UnsignedSignatureProperties + "xades:SigAndRefsTimeStamp/xades:EncapsulatedTimeStamp", ns) is not XmlElement encapsulated)
        {
            return null;
        }

        try
        {
            byte[] token = DecodeBase64(encapsulated);
            byte[] input = XadesSignatureBuilder.CreateSigAndRefsTimeStampInput(sigElement, ns);
            var check = TimestampToken.Verify(token, input);
            if (!check.IsValid)
            {
                warnings.Add("XAdES-X: SigAndRefsTimeStamp is invalid: " + string.Join("; ", check.Errors));
            }

            return check.IsValid;
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or CryptographicException)
        {
            warnings.Add($"XAdES-X: SigAndRefsTimeStamp could not be checked: {ex.Message}");
            return false;
        }
    }

    /// <summary>Reads SignerRoleV2 (or the SignerRole it obsoletes): claimed roles, attribute certificates and signed assertions.</summary>
    private static (IReadOnlyList<string> Claimed, IReadOnlyList<ReadOnlyMemory<byte>> AttributeCertificates, IReadOnlyList<string> SignedAssertions)
        ReadSignerRoles(XmlElement sigElement, XmlNamespaceManager ns, List<string> warnings)
    {
        const string properties = "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/";
        var claimed = new List<string>();
        var attributeCertificates = new List<ReadOnlyMemory<byte>>();
        var signedAssertions = new List<string>();
        if ((sigElement.SelectSingleNode(properties + "xades:SignerRoleV2", ns)
                ?? sigElement.SelectSingleNode(properties + "xades:SignerRole", ns)) is not XmlElement signerRole)
        {
            return (claimed, attributeCertificates, signedAssertions);
        }

        foreach (XmlElement role in signerRole.SelectNodes("xades:ClaimedRoles/xades:ClaimedRole", ns)!)
        {
            claimed.Add(role.InnerText.Trim());
        }

        foreach (XmlElement certificate in signerRole.SelectNodes("xades:CertifiedRolesV2/xades:CertifiedRole/xades:X509AttributeCertificate", ns)!)
        {
            try
            {
                attributeCertificates.Add(DecodeBase64(certificate));
            }
            catch (FormatException)
            {
                warnings.Add("An X509AttributeCertificate of SignerRoleV2 is not valid base64.");
            }
        }

        foreach (XmlElement assertion in signerRole.SelectNodes("xades:SignedAssertions/xades:SignedAssertion", ns)!)
        {
            signedAssertions.Add(assertion.InnerXml);
        }

        return (claimed, attributeCertificates, signedAssertions);
    }

    /// <summary>Reads SignedSignatureProperties/SignaturePolicyIdentifier/SignaturePolicyId, if any.</summary>
    /// <summary>
    /// The encapsulated revocation values of the signature's RevocationValues (ETSI EN 319 132-1 §5.5.2): the DER CRLs
    /// (<c>CRLValues/EncapsulatedCRLValue</c>) or OCSP responses (<c>OCSPValues/EncapsulatedOCSPValue</c>).
    /// </summary>
    private static List<byte[]> EmbeddedValues(XmlElement sigElement, XmlNamespaceManager ns, string container, string element)
    {
        var values = new List<byte[]>();
        string path = "xades:RevocationValues/xades:" + container + "/xades:" + element;
        var nodes = sigElement.SelectNodes(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/" + path
            + " | ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" + path, ns);
        if (nodes is null)
        {
            return values;
        }

        foreach (XmlElement node in nodes)
        {
            try
            {
                values.Add(Convert.FromBase64String(node.InnerText.Trim()));
            }
            catch (FormatException)
            {
                // Not base64: the online sources decide.
            }
        }

        return values;
    }

    private static SignaturePolicyReference? ReadSignaturePolicy(XmlElement sigElement, XmlNamespaceManager ns)
    {
        if (sigElement.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignaturePolicyIdentifier/xades:SignaturePolicyId",
                ns) is not XmlElement policyId
            || policyId.SelectSingleNode("xades:SigPolicyId/xades:Identifier", ns) is not XmlElement identifier)
        {
            return null;
        }

        string oid = identifier.InnerText.Trim();
        if (oid.StartsWith("urn:oid:", StringComparison.OrdinalIgnoreCase))
        {
            oid = oid["urn:oid:".Length..];
        }

        string? hashOid = null;
        byte[] hash = [];
        if (policyId.SelectSingleNode("xades:SigPolicyHash", ns) is XmlElement policyHash
            && policyHash.SelectSingleNode("ds:DigestValue", ns) is XmlElement digestValue)
        {
            try
            {
                hash = DecodeBase64(digestValue);
                hashOid = DetectHashAlgorithm((XmlElement?)policyHash.SelectSingleNode("ds:DigestMethod", ns)).Name switch
                {
                    "SHA1" => Oids.Sha1,
                    "SHA384" => Oids.Sha384,
                    "SHA512" => Oids.Sha512,
                    _ => Oids.Sha256,
                };
            }
            catch (FormatException)
            {
                hash = [];
            }
        }

        string? uri = policyId.SelectSingleNode("xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades:SPURI", ns)?.InnerText.Trim();
        return new SignaturePolicyReference(oid, hashOid, hash, string.IsNullOrEmpty(uri) ? null : uri);
    }

    private static HashAlgorithmName DetectHashAlgorithm(XmlElement? digestMethodEl)
    {
        if (digestMethodEl is null)
        {
            return HashAlgorithmName.SHA256;
        }

        string? alg = digestMethodEl.GetAttribute("Algorithm");
        if (string.IsNullOrEmpty(alg))
        {
            return HashAlgorithmName.SHA256;
        }

        try
        {
            return XmlDSigUrls.GetHashAlgorithmFromUri(alg);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception)
        {
            return HashAlgorithmName.SHA256;
        }
    }

    /// <summary>The token of the SignatureTimeStamp property, or null when there is none or it cannot be read.</summary>
    private static byte[]? SignatureTimeStampToken(XmlElement sigElement, XmlNamespaceManager ns)
    {
        var encapsulated = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties" +
            "/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:SignatureTimeStamp")
            ?.SelectSingleNode("xades:EncapsulatedTimeStamp", ns);
        try
        {
            return encapsulated is null ? null : DecodeBase64(encapsulated);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private TimestampTokenValidationResult ValidateSignatureTimeStamp(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        DateTimeOffset? signingTime,
        IEnumerable<X509Certificate2>? trustAnchors,
        List<string> warnings)
    {
        var tsEl = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties" +
            "/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:SignatureTimeStamp");

        if (tsEl is null)
        {
            return new TimestampTokenValidationResult();
        }

        var encTs = tsEl.SelectSingleNode("xades:EncapsulatedTimeStamp", ns);
        if (encTs is null)
        {
            warnings.Add("SignatureTimeStamp element found but no EncapsulatedTimeStamp.");
            return new TimestampTokenValidationResult { IsIntegrityValid = false };
        }

        byte[] timestampToken;
        try
        {
            timestampToken = DecodeBase64(encTs);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            warnings.Add($"EncapsulatedTimeStamp contains invalid base64: {ex.Message}");
            return new TimestampTokenValidationResult { IsIntegrityValid = false };
        }

        TimestampValidator.CertificateChainValidatorDelegate? validateTsaChain = null;
        // Without anchors given to this call, the TSA is judged against the configured roots (as the content and
        // archive timestamps are), so the signature time-stamp can give a proof of existence.
        IEnumerable<X509Certificate2>? tsaAnchors = trustAnchors ?? _options.TrustedRoots;
        if (tsaAnchors is not null)
        {
            validateTsaChain = (tsaCert, embeddedCerts, tsaErrors, tsaWarnings) =>
            {
                if (tsaCert is null)
                {
                    tsaErrors.Add("TSA certificate not found.");
                    return false;
                }

                using var chain = new X509Chain
                {
                    ChainPolicy =
                    {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        RevocationMode = X509RevocationMode.NoCheck
                    }
                };
                foreach (var anchor in tsaAnchors)
                {
                    chain.ChainPolicy.CustomTrustStore.Add(anchor);
                }
                foreach (var certificate in embeddedCerts)
                {
                    chain.ChainPolicy.ExtraStore.Add(certificate);
                }

                if (chain.Build(tsaCert))
                {
                    return true;
                }

                foreach (var status in chain.ChainStatus)
                {
                    tsaErrors.Add($"TSA chain: {status.Status} \u2014 {status.StatusInformation}");
                }
                return false;
            };
        }

        byte[] canonicalizedSignatureValue;
        try
        {
            canonicalizedSignatureValue = XadesSignatureBuilder.CreateSignatureTimeStampInput(
                System.Text.Encoding.UTF8.GetBytes(sigElement.OwnerDocument!.OuterXml),
                sigElement.GetAttribute("Id"));
        }
        catch (Exception ex) when (ex is XmlException or InvalidOperationException or CryptographicException)
        {
            warnings.Add($"Could not canonicalize SignatureValue for SignatureTimeStamp: {ex.Message}");
            return new TimestampTokenValidationResult { IsIntegrityValid = false };
        }

        var timestampWarnings = new List<string>();
        TimestampTokenValidationResult tsResult = _timestampValidator.ValidateWithTrust(
            timestampToken,
            canonicalizedSignatureValue,
            signingTime,
            timestampWarnings,
            validateTsaChain,
            null);

        warnings.AddRange(timestampWarnings);

        // If TimestampValidator returns null (e.g. parsing failure), treat as invalid
        // since the timestamp element is present but unverifiable.
        return new TimestampTokenValidationResult
        {
            IsIntegrityValid = tsResult.IsIntegrityValid ?? false,
            IsTsaTrusted = tsResult.IsTsaTrusted,
            GenTime = tsResult.GenTime,
        };
    }

    private static bool? ValidateArchiveTimeStamp(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        XadesDetachedData? originalData,
        List<string> warnings)
    {
        // Try xades141 namespace first, fall back to xades; try nested then flat
        var atsEl = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties" +
            "/xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades141:ArchiveTimeStamp");

        atsEl ??= SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties" +
            "/xades:UnsignedSignatureProperties/xades:ArchiveTimeStamp",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:ArchiveTimeStamp");

        if (atsEl is null)
        {
            return null;
        }

        var encTs = atsEl.SelectSingleNode("xades:EncapsulatedTimeStamp", ns) ?? atsEl.SelectSingleNode("xades141:EncapsulatedTimeStamp", ns);

        if (encTs is null)
        {
            warnings.Add("ArchiveTimeStamp element found but no EncapsulatedTimeStamp.");
            return false;
        }

        try
        {
            _ = DecodeBase64(encTs);
            byte[] signedXml = System.Text.Encoding.UTF8.GetBytes(sigElement.OwnerDocument!.OuterXml);
            return XadesSignatureBuilder.ValidateArchiveTimeStamp(
                signedXml,
                originalData,
                warnings,
                sigElement.GetAttribute("Id"));
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            warnings.Add($"ArchiveTimeStamp validation failed: {ex.Message}");
            return false;
        }
    }

    private static bool? ValidateLtvData(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        X509Certificate2? signerCert,
        DateTimeOffset? signingTime,
        List<string> warnings)
    {
        var certValues = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CertificateValues",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:CertificateValues");

        var revValues = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:RevocationValues",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:RevocationValues");

        if (certValues is null && revValues is null)
        {
            return null;
        }

        bool revValuesValid = true;
        var certificates = new List<X509Certificate2>();
        var ocsps = new List<byte[]>();
        var crls = new List<byte[]>();

        try
        {
            // Validate CertificateValues
            if (certValues is not null)
            {
                try
                {
                    var certNodes = certValues.SelectNodes("xades:EncapsulatedX509Certificate", ns);
                    if (certNodes is null || certNodes.Count == 0)
                    {
                        warnings.Add("CertificateValues element is empty.");
                        return false;
                    }

                    bool hasSigner = false;
                    foreach (XmlElement certEl in certNodes)
                    {
                        try
                        {
                            byte[] rawData = DecodeBase64(certEl);
                            if (signerCert is not null && rawData.AsSpan().SequenceEqual(signerCert.RawData))
                            {
                                hasSigner = true;
                            }
                            // Validate that the DER blob is parseable
                            certificates.Add(CertificateLoader.LoadCertificate(rawData));
                        }
                        // S2221: intentional -- validation pipeline converts exceptions to error messages
                        catch (Exception ex)
                        {
                            warnings.Add($"CertificateValues contains invalid X.509 certificate data: {ex.Message}");
                            return false;
                        }
                    }

                    if (!hasSigner && signerCert is not null)
                    {
                        warnings.Add("CertificateValues does not include the signer certificate.");
                    }
                }
                // S2221: intentional -- validation pipeline converts exceptions to error messages
                catch (Exception ex)
                {
                    warnings.Add($"Failed to validate CertificateValues: {ex.Message}");
                    return false;
                }
            }

            // Validate RevocationValues
            if (revValues is not null)
            {
                try
                {
                    // Check OCSP responses
                    var ocspNodes = revValues.SelectNodes(
                        "xades:OCSPValues/xades:EncapsulatedOCSPValue", ns);
                    if (ocspNodes is not null)
                    {
                        foreach (XmlElement ocspEl in ocspNodes)
                        {
                            try
                            {
                                byte[] ocspData = DecodeBase64(ocspEl);
                                // Validate that the OCSP response is parseable DER
                                var reader = new System.Formats.Asn1.AsnReader(
                                    ocspData, System.Formats.Asn1.AsnEncodingRules.DER);
                                reader.ReadSequence(); // OCSP response is a SEQUENCE
                                ocsps.Add(ocspData);
                            }
                            // S2221: intentional -- validation pipeline converts exceptions to error messages
                            catch (Exception ex)
                            {
                                warnings.Add($"EncapsulatedOCSPValue contains invalid data: {ex.Message}");
                                revValuesValid = false;
                            }
                        }
                    }

                    // Check CRLs
                    var crlNodes = revValues.SelectNodes(
                        "xades:CRLValues/xades:EncapsulatedCRLValue", ns);
                    if (crlNodes is not null)
                    {
                        foreach (XmlElement crlEl in crlNodes)
                        {
                            try
                            {
                                byte[] crlData = DecodeBase64(crlEl);
                                // Validate that the CRL data is parseable as DER
                                var reader = new System.Formats.Asn1.AsnReader(crlData, System.Formats.Asn1.AsnEncodingRules.DER);
                                reader.ReadSequence();
                                crls.Add(crlData);
                            }
                            // S2221: intentional -- validation pipeline converts exceptions to error messages
                            catch (Exception ex)
                            {
                                warnings.Add($"EncapsulatedCRLValue contains invalid data: {ex.Message}");
                                revValuesValid = false;
                            }
                        }
                    }
                }
                // S2221: intentional -- validation pipeline converts exceptions to error messages
                catch (Exception ex)
                {
                    warnings.Add($"Failed to validate RevocationValues: {ex.Message}");
                    revValuesValid = false;
                }
            }

            if (!revValuesValid)
            {
                warnings.Add("RevocationValues validation failed.");
                return false;
            }

            if (certValues is null || revValues is null || certificates.Count == 0 ||
                ocsps.Count == 0 && crls.Count == 0 ||
                signerCert is not null && !certificates.Any(cert => cert.RawData.AsSpan().SequenceEqual(signerCert.RawData)))
            {
                warnings.Add("XAdES-B-LT: Certificate or revocation values are incomplete.");
                return false;
            }

            if (!EmbeddedRevocationEvidence.CoversAll(
                    certificates, ocsps, crls, signingTime ?? DateTimeOffset.UtcNow, RevocationEvidence.MatchingOcspClient()))
            {
                warnings.Add("XAdES-B-LT: Embedded revocation evidence is not authenticated or does not cover the certificate paths.");
                return false;
            }

            return true;
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static XmlElement? SelectByNestedPath(
        XmlElement root,
        XmlNamespaceManager ns,
        string nestedPath,
        string flatPath)
    {
        return root.SelectSingleNode(nestedPath, ns) as XmlElement
            ?? root.SelectSingleNode(flatPath, ns) as XmlElement;
    }
}

/// <summary>The data a ds:Reference points to is not in the document and was not given (a detached signature validated alone).</summary>
internal sealed class ReferenceDataNotFoundException(string message) : NotSupportedException(message);
