using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Policies;

namespace SimpleSign.Core.Validation.Policy;

/// <summary>What a format validator found, in the terms the evaluator needs. A null fact was not established.</summary>
internal sealed record ValidationFacts
{
    public bool IsIntegrityValid { get; init; }
    public bool IsSignatureValid { get; init; }
    public bool IsSignatureVerificationIndeterminate { get; init; }
    public X509Certificate2? SignerCertificate { get; init; }
    public bool IsCertificateChainValid { get; init; }
    public bool IsChainTrustWarning { get; init; }

    /// <summary>Whether the chain reaches a trust anchor and fails, if at all, only for revocation or time; null: not established.</summary>
    public bool? ChainReachesAnchor { get; init; }

    /// <summary>Whether the chain is trusted enough for its revocation to be checked.</summary>
    public bool IsChainAnchored => ChainReachesAnchor ?? (IsCertificateChainValid || IsChainTrustWarning);

    /// <summary>True: not revoked; false: revoked or unknown (see <see cref="RevocationSource"/>); null: not checked.</summary>
    public bool? IsNotRevoked { get; init; }
    public RevocationSource RevocationSource { get; init; }
    public bool IsDocumentTimestamp { get; init; }
    public bool? IsTsaTrusted { get; init; }
    public string? DigestAlgorithmOid { get; init; }

    /// <summary>The OID of the signature algorithm (RSASSA-PSS changes the key's algorithm name), or null.</summary>
    public string? SignatureAlgorithmOid { get; init; }

    /// <summary>A trusted time the signature is proven to exist at (signature timestamp), or null.</summary>
    public DateTimeOffset? ProofOfExistence { get; init; }
    public DateTimeOffset ValidationTime { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>The certificate chain, signing certificate first, trust anchor last; null when not given.</summary>
    public IReadOnlyList<X509Certificate2>? Chain { get; init; }

    /// <summary>The time the revocation data was issued (CRL thisUpdate, OCSP producedAt), or null.</summary>
    public DateTimeOffset? RevocationIssuedAt { get; init; }

    /// <summary>The signing time claimed in the signature (signing-time, SigningTime, PDF /M), or null when absent or unknown.</summary>
    public DateTimeOffset? ClaimedSigningTime { get; init; }

    /// <summary>Whether the signing time was looked for; false leaves the signing time constraints not checked.</summary>
    public bool SigningTimeKnown { get; init; }

    /// <summary>Whether a reference to the signing certificate (ESS signing-certificate(-v2), XAdES SigningCertificate) is present; null: not established.</summary>
    public bool? HasSigningCertificateReference { get; init; }

    /// <summary>Whether that reference matches the signing certificate; null: not established.</summary>
    public bool? SigningCertificateReferenceMatches { get; init; }

    /// <summary>The OID of the signature policy the signature names, or null.</summary>
    public string? SignaturePolicyOid { get; init; }

    /// <summary>Whether the signature policy identifier was looked for.</summary>
    public bool SignaturePolicyKnown { get; init; }

    /// <summary>Whether the policy document's hash matches the one in the signature; null: not established.</summary>
    public bool? PolicyHashMatches { get; init; }

    /// <summary>The trusted lists the trust anchors come from, for the TrustedLists constraints; null when none.</summary>
    public IReadOnlyList<Extensions.TrustedListInfo>? TrustedLists { get; init; }

    /// <summary>The signed attributes (CAdES, PAdES) or signed properties (XAdES); null when not read.</summary>
    public SignedAttributeFacts? SignedAttributes { get; init; }

    /// <summary>The unsigned attributes (timestamps, countersignatures) present; null when not read.</summary>
    public UnsignedAttributeFacts? UnsignedAttributes { get; init; }

    /// <summary>The format and level of the signature (<c>PAdES-BASELINE-LT</c>, <c>CAdES-BASELINE-B</c>…); null when not established.</summary>
    public string? SignatureFormat { get; init; }

    /// <summary>Whether the signature covers the whole document (a later PDF revision makes it partial); null when not established.</summary>
    public bool? CoversWholeDocument { get; init; }

    /// <summary>Whether the signed data was found (the document, the detached content); null when not established.</summary>
    public bool? SignedDataFound { get; init; }

    /// <summary>Whether the signature carries the signature policy document; null when not established.</summary>
    public bool? PolicyStorePresent { get; init; }

    /// <summary>Whether the signature policy document was obtained (from the signature or elsewhere); null when not established.</summary>
    public bool? PolicyDocumentAvailable { get; init; }

    /// <summary>How many SignerInfos the CMS SignedData has; null for other formats.</summary>
    public int? SignerInfoCount { get; init; }

    /// <summary>Whether the PDF ByteRange is well formed; null for other formats.</summary>
    public bool? ByteRangeValid { get; init; }

    /// <summary>Whether the ByteRange of the document's last signature covers the whole file; null when it is not the last one or not a PDF.</summary>
    public bool? ByteRangeCoversDocument { get; init; }

    /// <summary>Whether the ByteRange collides with another signature's (the same ranges, or overlapping /Contents); null for other formats.</summary>
    public bool? ByteRangeCollides { get; init; }

    /// <summary>Whether no later PDF revision redefines the signature dictionary with another ByteRange or Contents; null for other formats.</summary>
    public bool? SignatureDictionaryConsistent { get; init; }

    /// <summary>
    /// The errors of the signature's structure: the CMS decoded (CAdES, PAdES), the XML Signature and XAdES schemas
    /// (XAdES); empty when it is valid, null when not checked.
    /// </summary>
    public IReadOnlyList<string>? StructureErrors { get; init; }

    /// <summary>What the PDF revisions after the signature changed; null for other formats.</summary>
    public PdfChangeFacts? PdfChanges { get; init; }

    /// <summary>Whether no other element of the document has the signature's Id (XAdES); null for other formats.</summary>
    public bool? SignatureIdUnique { get; init; }

    /// <summary>The CRLs the signature carries (DSS, revocation values); their facts are evaluated in the Revocation context.</summary>
    public IReadOnlyList<byte[]>? EmbeddedCrls { get; init; }

    /// <summary>The OCSP responses the signature carries.</summary>
    public IReadOnlyList<byte[]>? EmbeddedOcsps { get; init; }

    /// <summary>The signature and archive timestamps, evaluated in the Timestamp context; null when not looked at.</summary>
    public IReadOnlyList<TimestampTokenFacts>? Timestamps { get; init; }

    /// <summary>Whether the signature is a countersignature: it is evaluated in the CounterSignatureConstraints context.</summary>
    public bool IsCounterSignature { get; init; }
}

/// <summary>The unsigned attributes of a signature, in the terms of the <c>UnsignedAttributes</c> constraints.</summary>
internal sealed record UnsignedAttributeFacts
{
    public bool CounterSignature { get; init; }

    public bool SignatureTimeStamp { get; init; }

    public bool ValidationDataTimeStamp { get; init; }

    public bool ValidationDataRefsOnlyTimeStamp { get; init; }

    public bool ArchiveTimeStamp { get; init; }

    public bool DocumentTimeStamp { get; init; }

    /// <summary>Whether a valid T-level timestamp (signature or document timestamp) is present; null when not established.</summary>
    public bool? TLevelTimeStampValid { get; init; }

    /// <summary>Whether a valid LTA-level timestamp (archive or later document timestamp) is present; null when not established.</summary>
    public bool? LtaLevelTimeStampValid { get; init; }
}

/// <summary>The indication, sub-indication and checks of a validation.</summary>
internal sealed record ValidationEvaluation(
    SignatureIndication Indication,
    SignatureSubIndication? SubIndication,
    IReadOnlyList<ValidationConstraintResult> Constraints,
    IReadOnlyList<string> Warnings)
{
    /// <summary>The policy the evaluation applied.</summary>
    public AppliedPolicy? Policy { get; init; }

    /// <summary>The timestamps and revocation data evaluated as tokens, with their outcome.</summary>
    public IReadOnlyList<ValidationObjectEntry> ValidationObjects { get; init; } = [];

    /// <summary>The best signature time: the earliest accepted signature timestamp, or null.</summary>
    public DateTimeOffset? BestSignatureTime { get; init; }
}

/// <summary>
/// Turns the facts of a validation into an ETSI EN 319 102-1 outcome under a <see cref="ValidationPolicy"/>: each
/// constraint of the policy that applies is evaluated with its level and reported with its path as id; the first FAIL decides the indication and sub-indication. Constraints of the policy that
/// SimpleSign does not evaluate are reported as not checked.
/// </summary>
internal static class ValidationPolicyEvaluator
{
    private const string Signature = "SignatureConstraints";
    private const string Timestamp = "Timestamp";

    private const string Revocation = "Revocation";

    internal static ValidationEvaluation Evaluate(ValidationFacts facts, ValidationPolicy policy) =>
        new Evaluation(facts, policy.Tree).Run() with { Policy = AppliedPolicy.Of(policy) };

    /// <summary>
    /// One evaluation: the facts, the policy and what was found so far. A nested evaluation judges a token of the
    /// signature (a timestamp, a CRL or OCSP response) in its own context: its FAILs make the token unusable, they do not
    /// decide the signature's indication.
    /// </summary>
    private sealed class Evaluation(
        ValidationFacts facts,
        PolicyTree tree,
        string? tokenContext = null,
        string? label = null,
        RevocationTokenFacts? revocationToken = null,
        TimestampTokenFacts? timestampToken = null,
        (DateTimeOffset? GenTime, X500DistinguishedName? Tsa, bool TsaPresent) tstInfo = default)
    {
        private readonly List<ValidationConstraintResult> _constraints = [];
        private readonly List<string> _warnings = [];
        private readonly HashSet<string> _evaluated = new(StringComparer.Ordinal);
        private readonly List<(RevocationTokenFacts Token, bool Accepted)> _revocationTokens = [];
        private readonly List<ValidationObjectEntry> _objects = [];
        private (SignatureIndication Indication, SignatureSubIndication? Sub)? _decided;
        private DateTimeOffset? _proofOfExistence = facts.ProofOfExistence;

        private DateTimeOffset ReferenceTime => _proofOfExistence ?? facts.ValidationTime;

        private bool Nested => tokenContext is not null;

        /// <summary>The context of the signature's own constraints: a countersignature has its own.</summary>
        private string SignatureContext => facts.IsCounterSignature ? "CounterSignatureConstraints" : Signature;

        public ValidationEvaluation Run()
        {
            // A document timestamp is a timestamp token: the Timestamp constraints apply to it.
            string context = tokenContext ?? (facts.IsDocumentTimestamp ? Timestamp : SignatureContext);
            string basic = context + "/BasicSignatureConstraints";
            if (!Nested)
            {
                EvaluateTimestampTokens();
                EvaluateRevocationTokens();
            }

            EvaluateBasic(basic);
            EvaluateSigningCertificate(basic + "/SigningCertificate");
            EvaluateCaCertificates(basic + "/CACertificate");
            EvaluateSignatureCrypto(basic);
            EvaluateChain(basic);
            if (revocationToken is not null)
            {
                EvaluateRevocationToken(revocationToken);
            }
            else if (timestampToken is not null)
            {
                EvaluateSignedAttributes(Timestamp + "/SignedAttributes");
                EvaluateTimestampToken(timestampToken);
            }
            else if (!facts.IsDocumentTimestamp)
            {
                EvaluateSignatureConstraints();
                EvaluateSignedAttributes(SignatureContext + "/SignedAttributes");
                EvaluateUnsignedAttributes(SignatureContext + "/UnsignedAttributes");
                EvaluateTimestampDelay();
                EvaluateBestSignatureTime();
            }

            EvaluateTrustService(basic);
            ReportNotEvaluated(context);
            if (!Nested && EvaluateTrustedList())
            {
                ReportNotEvaluated("TrustedLists");
            }

            var outcome = _decided ?? (SignatureIndication.Valid, null);
            return new ValidationEvaluation(outcome.Indication, outcome.Sub, _constraints, _warnings)
            {
                ValidationObjects = _objects,
                BestSignatureTime = _proofOfExistence,
            };
        }

        // ── Tokens: timestamps and revocation data, each in its own context ───────────────

        /// <summary>
        /// Evaluates each timestamp in the Timestamp context. A signature timestamp that fails there is not a proof of
        /// existence; the earliest one that passes is.
        /// </summary>
        private void EvaluateTimestampTokens()
        {
            if (facts.Timestamps is not { Count: > 0 } timestamps)
            {
                return;
            }

            var accepted = new List<(TimestampTokenKind Kind, DateTimeOffset Time)>();
            var all = new List<(TimestampTokenKind Kind, DateTimeOffset Time)>();
            foreach (var token in timestamps)
            {
                if (token.Trusted is null)
                {
                    continue; // A TSA no one could judge is not evaluated: it would only show as an untrusted chain.
                }

                Crypto.CmsSignedData cms;
                try
                {
                    cms = Crypto.CmsParser.Parse(token.Token);
                }
                catch (Exception ex) when (ex is System.Formats.Asn1.AsnContentException or InvalidDataException or System.Security.Cryptography.CryptographicException)
                {
                    continue;
                }

                var info = TstInfoReader.FromToken(token.Token);
                var tokenFacts = new ValidationFacts
                {
                    IsIntegrityValid = token.ImprintValid ?? false,
                    IsSignatureValid = TimestampValidator.VerifyTokenSignature(token.Token),
                    SignerCertificate = cms.SignerCertificate,
                    IsCertificateChainValid = token.Trusted == true,
                    ChainReachesAnchor = token.Trusted,
                    DigestAlgorithmOid = cms.DigestAlgorithmOid,
                    ProofOfExistence = info.GenTime,
                    ValidationTime = facts.ValidationTime,
                }.WithCms(cms);
                var evaluation = new Evaluation(tokenFacts, tree, Timestamp, token.Label, timestampToken: token, tstInfo: info).Run();
                var nested = Merge(evaluation);
                _objects.Add(ObjectOf(ValidationObjectType.Timestamp, token.Token, evaluation) with { Time = info.GenTime });
                if (info.GenTime is { } time)
                {
                    all.Add((token.Kind, time));
                    if (!nested && token.ImprintValid == true && token.Trusted == true)
                    {
                        accepted.Add((token.Kind, time));
                    }
                }
            }

            // The best signature time: the earliest accepted signature timestamp (EN 319 102-1 §5.6.2.4).
            var signatureTimes = accepted.Where(t => t.Kind == TimestampTokenKind.Signature).Select(t => t.Time).ToList();
            _proofOfExistence = signatureTimes.Count > 0 ? signatureTimes.Min() : null;

            var contents = all.Where(t => t.Kind == TimestampTokenKind.Content).Select(t => t.Time).ToList();
            var signatures = all.Where(t => t.Kind == TimestampTokenKind.Signature).Select(t => t.Time).ToList();
            var archives = all.Where(t => t.Kind == TimestampTokenKind.Archive).Select(t => t.Time).ToList();
            // Content timestamps, then signature timestamps, then archive timestamps (EN 319 102-1 §5.6.2.1).
            if ((contents.Count > 0 && (signatures.Count > 0 || archives.Count > 0)) || (signatures.Count > 0 && archives.Count > 0))
            {
                bool ordered = (contents.Count == 0 || contents.Max() <= signatures.Concat(archives).Min())
                    && (signatures.Count == 0 || archives.Count == 0 || signatures.Max() <= archives.Min());
                Check(Timestamp + "/Coherence", ordered,
                    "The timestamps are in order: content, signature, archive.",
                    "The timestamps are out of order (a later kind is earlier than an earlier one).", SignatureIndication.Indeterminate, SignatureSubIndication.TimestampOrderFailure);
            }

        }

        /// <summary>Evaluates each CRL and OCSP response the signature carries in the Revocation context.</summary>
        private void EvaluateRevocationTokens()
        {
            if (facts.Chain is not { Count: > 1 } chain || (facts.EmbeddedCrls is null && facts.EmbeddedOcsps is null))
            {
                return;
            }

            foreach (var token in RevocationTokenReader.Read(chain, facts.EmbeddedCrls ?? [], facts.EmbeddedOcsps ?? []))
            {
                var tokenFacts = new ValidationFacts
                {
                    IsIntegrityValid = true,
                    IsSignatureValid = token.SignatureValid,
                    SignerCertificate = token.Issuer,
                    Chain = token.IssuerChain.Count > 0 ? token.IssuerChain : null,
                    IsCertificateChainValid = token.Issuer is not null && facts.IsCertificateChainValid,
                    ChainReachesAnchor = token.Issuer is null ? false : facts.ChainReachesAnchor,
                    SignatureAlgorithmOid = token.SignatureAlgorithmOid,
                    DigestAlgorithmOid = token.SignatureAlgorithmOid is { } oid ? CryptographicRules.DigestOidOf(oid) : null,
                    // The issuer of revocation data is judged when it produced it.
                    ProofOfExistence = token.ProducedAt,
                    ValidationTime = facts.ValidationTime,
                };
                var evaluation = new Evaluation(tokenFacts, tree, Revocation, token.Label, revocationToken: token).Run();
                bool failed = Merge(evaluation);
                _objects.Add(ObjectOf(token.Kind == RevocationTokenKind.Crl ? ValidationObjectType.Crl : ValidationObjectType.OcspResponse, token.Data, evaluation));
                _revocationTokens.Add((token, !failed && token.Status != RevocationTokenStatus.Unknown));
            }
        }

        /// <summary>A token as a validation object: usable (valid) unless one of its constraints failed.</summary>
        private static ValidationObjectEntry ObjectOf(ValidationObjectType type, byte[] data, ValidationEvaluation evaluation) =>
            evaluation.Constraints.Any(c => c.Status == ConstraintStatus.Failed)
                ? new(type, data, evaluation.Indication == SignatureIndication.Valid ? SignatureIndication.Indeterminate : evaluation.Indication, evaluation.SubIndication)
                : new(type, data, SignatureIndication.Valid, null);

        /// <summary>Adds a nested evaluation's results; true when one of its constraints failed.</summary>
        private bool Merge(ValidationEvaluation nested)
        {
            foreach (var constraint in nested.Constraints)
            {
                if (constraint.Status == ConstraintStatus.NotChecked && !_evaluated.Add(constraint.Id))
                {
                    continue;
                }

                _evaluated.Add(constraint.Id);
                _constraints.Add(constraint);
            }

            _warnings.AddRange(nested.Warnings);
            return nested.Constraints.Any(c => c.Status == ConstraintStatus.Failed);
        }

        /// <summary>The constraints of the Revocation context that read the CRL or OCSP response itself.</summary>
        private void EvaluateRevocationToken(RevocationTokenFacts token)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.TryLater;
            Check(Revocation + "/UnknownStatus", token.Status != RevocationTokenStatus.Unknown, "The status is known.", "The status is unknown.", I, S);
            Check(Revocation + "/ThisUpdatePresent", token.ThisUpdate is not null, "thisUpdate is present.", "thisUpdate is missing.", I, S);
            Check(Revocation + "/RevocationIssuerKnown", token.Issuer is not null, "Its issuer is known.", "Its issuer was not found.", I, S);
            if (token.Issuer is { } issuer && token.ProducedAt is { } produced)
            {
                Check(Revocation + "/RevocationIssuerValidAtProductionTime",
                    issuer.NotBefore.ToUniversalTime() <= produced && issuer.NotAfter.ToUniversalTime() >= produced,
                    "Its issuer was valid when it produced it.", $"Its issuer was not valid at {produced:yyyy-MM-dd HH:mm} UTC.", I, S);
            }

            if (token.ThisUpdate is { } thisUpdate)
            {
                Check(Revocation + "/RevocationAfterCertificateIssuance", thisUpdate >= token.Certificate.NotBefore.ToUniversalTime(),
                    "It was issued after the certificate.", "It was issued before the certificate.", I, S);
            }

            if (token.ThisUpdate is { } issued)
            {
                var notAfter = token.Certificate.NotAfter.ToUniversalTime();
                // RFC 5280 §3.3 / RFC 6960: once a certificate expired, the data says something about it only when it
                // keeps expired certificates (expiredCertsOnCRL, archiveCutoff) from before the expiry.
                Check(Revocation + "/RevocationHasInformationAboutCertificate",
                    notAfter >= issued || token.ExpiredCertificatesSince is { } since && since <= notAfter,
                    "It covers the certificate.",
                    "It was issued after the certificate expired and keeps no status of expired certificates (expiredCertsOnCRL, archiveCutoff).", I, S);
            }

            Fact(Revocation + "/OCSPResponderIdMatch", token.ResponderIdMatches, "The ResponderID designates the responder.",
                "The ResponderID designates no certificate of the response.", I, S);
            if (token.Kind == RevocationTokenKind.Ocsp)
            {
                Check(Revocation + "/SelfIssuedOCSP", token.IssuerChain.All(c => !c.RawData.AsSpan().SequenceEqual(token.Certificate.RawData)),
                    "It is not signed by the certificate it is about.", "It is signed by the certificate it is about.", I, S);
            }
            else
            {
                NotApplicable(Revocation + "/SelfIssuedOCSP");
            }
        }

        /// <summary>The constraints of the Timestamp context that read the token itself.</summary>
        private void EvaluateTimestampToken(TimestampTokenFacts token)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.SigConstraintsFailure;
            Check(Timestamp + "/TimestampValid", token.ImprintValid == true && facts.IsSignatureValid && token.Trusted == true,
                "The timestamp is valid.", "The timestamp is not valid (its imprint, signature or TSA).", I, S);
            Check(Timestamp + "/TSAGeneralNamePresent", tstInfo.TsaPresent, "The timestamp names its TSA.", "The timestamp does not name its TSA.", I, S);
            if (tstInfo.Tsa is { } tsa && facts.SignerCertificate is { } tsaCertificate)
            {
                static IEnumerable<string> Parts(X500DistinguishedName name) =>
                    name.EnumerateRelativeDistinguishedNames().Select(r => r.GetSingleElementType().Value + "=" + r.GetSingleElementValue()).Order(StringComparer.Ordinal);
                Check(Timestamp + "/TSAGeneralNameContentMatch", Parts(tsa).SequenceEqual(Parts(tsaCertificate.SubjectName)),
                    "The TSA name matches the TSA certificate.", "The TSA name does not match the TSA certificate.", I, S);
                Check(Timestamp + "/TSAGeneralNameOrderMatch", tsa.RawData.AsSpan().SequenceEqual(tsaCertificate.SubjectName.RawData),
                    "The TSA name matches the TSA certificate, in order.", "The TSA name does not match the TSA certificate in order.", I, S);
            }
            else
            {
                NotApplicable(Timestamp + "/TSAGeneralNameContentMatch");
                NotApplicable(Timestamp + "/TSAGeneralNameOrderMatch");
            }

            Fact(Timestamp + "/AtsHashIndex", token.AtsHashIndexValid, "The ats-hash-index is right.", "The ats-hash-index is missing or wrong.", I, S);

            // These are the signature's, evaluated with all its timestamps, not with one token.
            foreach (string signatureLevel in new[] { "TimestampDelay", "Coherence", "RevocationTimeAgainstBestSignatureTime", "BestSignatureTimeBeforeExpirationDateOfSigningCertificate" })
            {
                NotApplicable(Timestamp + "/" + signatureLevel);
            }
        }

        /// <summary>The best signature time against the signing certificate's expiry and revocation.</summary>
        private void EvaluateBestSignatureTime()
        {
            if (_proofOfExistence is not { } best || facts.SignerCertificate is not { } signer)
            {
                return;
            }

            Check(Timestamp + "/BestSignatureTimeBeforeExpirationDateOfSigningCertificate", best <= signer.NotAfter.ToUniversalTime(),
                "The signature existed before the signing certificate expired.",
                $"The best signature time {best:yyyy-MM-dd HH:mm} UTC is after the signing certificate expired.",
                SignatureIndication.Indeterminate, SignatureSubIndication.OutOfBoundsNoPoe);
            if (_revocationTokens.Where(t => t.Accepted && t.Token.Status == RevocationTokenStatus.Revoked
                    && t.Token.Certificate.RawData.AsSpan().SequenceEqual(signer.RawData)).Select(t => t.Token.RevocationTime).FirstOrDefault() is { } revoked)
            {
                Check(Timestamp + "/RevocationTimeAgainstBestSignatureTime", revoked > best,
                    "The signing certificate was revoked after the signature was proven to exist.",
                    "The signing certificate was revoked before the signature was proven to exist.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.RevokedNoPoe);
            }
        }

        /// <summary>The revocation quality constraints of a certificate, from the tokens about it.</summary>
        private void EvaluateRevocationQuality(string path, X509Certificate2 certificate)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.TryLater;
            const SignatureSubIndication NoData = SignatureSubIndication.CertificateChainGeneralFailure;
            var tokens = _revocationTokens.Where(t => t.Token.Certificate.RawData.AsSpan().SequenceEqual(certificate.RawData)).ToList();
            if (tokens.Count == 0)
            {
                // Online revocation data is not kept: only what the checker concluded is known (the signing certificate).
                Fact(path + "/AcceptableRevocationDataFound",
                    path.EndsWith("/SigningCertificate", StringComparison.Ordinal) && facts.IsNotRevoked is not null
                        ? facts.RevocationSource is not (RevocationSource.None or RevocationSource.Indeterminate)
                        : null,
                    "Acceptable revocation data was found.", "No acceptable revocation data was found.", I, NoData);
                return;
            }

            string name = Name(certificate);
            Check(path + "/AcceptableRevocationDataFound", tokens.Any(t => t.Accepted),
                $"Acceptable revocation data was found for '{name}'.", $"No acceptable revocation data was found for '{name}'.", I, NoData);
            var crls = tokens.Where(t => t.Token.Kind == RevocationTokenKind.Crl).ToList();
            var ocsps = tokens.Where(t => t.Token.Kind == RevocationTokenKind.Ocsp).ToList();
            Fact(path + "/CRLNextUpdatePresent", crls.Count == 0 ? null : crls.All(t => t.Token.NextUpdate is not null),
                $"The CRLs of '{name}' have nextUpdate.", $"A CRL of '{name}' has no nextUpdate.", I, S);
            Fact(path + "/OCSPNextUpdatePresent", ocsps.Count == 0 ? null : ocsps.All(t => t.Token.NextUpdate is not null),
                $"The OCSP responses of '{name}' have nextUpdate.", $"An OCSP response of '{name}' has no nextUpdate.", I, S);
            var accepted = tokens.Where(t => t.Accepted).Select(t => t.Token).ToList();
            if (accepted.Count > 0)
            {
                Check(path + "/RevocationFreshnessNextUpdate", accepted.Any(t => t.NextUpdate is null || t.NextUpdate >= ReferenceTime || t.ThisUpdate >= ReferenceTime),
                    $"The revocation data of '{name}' is current.", $"The revocation data of '{name}' expired (nextUpdate) before {ReferenceTime:yyyy-MM-dd HH:mm} UTC.", I, S);
                Check(path + "/RevocationIssuerNotExpired", accepted.Any(t => t.Issuer is { } issuer
                        && issuer.NotBefore.ToUniversalTime() <= ReferenceTime && issuer.NotAfter.ToUniversalTime() >= ReferenceTime),
                    $"The issuer of the revocation data of '{name}' is within its validity.",
                    $"The issuer of the revocation data of '{name}' is not valid at {ReferenceTime:yyyy-MM-dd HH:mm} UTC.", I, NoData);
            }

            Check(path + "/NotOnHold", !tokens.Any(t => t.Token.Reason == 6), $"'{name}' is not on hold.", $"'{name}' is on hold (certificateHold).",
                SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
        }

        // ── Basic signature constraints ─────────────────────────────────────────────

        private void EvaluateBasic(string basic)
        {
            Check(basic + "/ReferenceDataIntact", facts.IsIntegrityValid,
                "The signed data matches the signature.", "The signed data does not match the signature.",
                SignatureIndication.Invalid, SignatureSubIndication.HashFailure);

            if (facts.IsSignatureVerificationIndeterminate)
            {
                Check(basic + "/SignatureIntact", false, "", "The signature algorithm is not supported.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.CryptoConstraintsFailure);
            }
            else
            {
                Check(basic + "/SignatureIntact", facts.IsSignatureValid,
                    "The signature value verifies with the signing certificate.",
                    "The signature value does not verify with the signing certificate.",
                    SignatureIndication.Invalid, SignatureSubIndication.SigCryptoFailure);
            }

            Fact(basic + "/ReferenceDataExistence", facts.SignedDataFound, "The signed data was found.", "The signed data was not found.",
                SignatureIndication.Indeterminate, SignatureSubIndication.SignedDataNotFound);
            Check(basic + "/SignatureValid", facts.IsIntegrityValid && facts.IsSignatureValid, "The signature is intact.", "The signature is not intact.",
                SignatureIndication.Invalid, SignatureSubIndication.SigCryptoFailure);
            Fact(basic + "/SignerInformationStore", facts.SignerInfoCount is { } count ? count == 1 : null,
                "The CMS has one SignerInfo.", $"The CMS has {facts.SignerInfoCount} SignerInfos; one is expected.",
                SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);
            Fact(basic + "/ByteRange", facts.ByteRangeValid, "The ByteRange is well formed.", "The ByteRange is not well formed.",
                SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);
            Fact(basic + "/ByteRangeAllDocument", facts.ByteRangeCoversDocument, "The last signature covers the whole file.",
                "Bytes were appended after the last signature.", SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);
            Fact(basic + "/ByteRangeCollision", facts.ByteRangeCollides is { } collides ? !collides : null,
                "The ByteRange does not collide with another signature's.", "The ByteRange collides with another signature's.",
                SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);
            Fact(basic + "/PdfSignatureDictionary", facts.SignatureDictionaryConsistent, "The signature dictionary is the same in every later revision.",
                "A later revision redefines the signature dictionary with another ByteRange or Contents.", SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);
            EvaluatePdfChanges(basic);
            Fact(basic + "/SignatureDuplicated", facts.SignatureIdUnique, "The signature's Id is unique.",
                "Another element of the document has the signature's Id.", SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);

            // Document timestamps whose chain is only a warning need a trusted TSA.
            if (facts.IsDocumentTimestamp && facts.IsChainTrustWarning && facts.IsTsaTrusted != true)
            {
                Decide(SignatureIndication.Indeterminate, SignatureSubIndication.NoCertificateChainFound);
            }

            string chain = basic + "/ProspectiveCertificateChain";
            // A chain that reaches its anchor and fails only for revocation or time is left to NotRevoked and NotExpired.
            if (facts.IsCertificateChainValid || facts.ChainReachesAnchor == true)
            {
                Check(chain, true, "The certificate chain reaches a trust anchor.", "", SignatureIndication.Indeterminate, SignatureSubIndication.NoCertificateChainFound);
            }
            else if (facts.IsChainTrustWarning)
            {
                _evaluated.Add(chain);
                _constraints.Add(new(chain, ConstraintStatus.Warning, null, "The chain is trusted by a country provider only."));
            }
            else
            {
                Check(chain, false, "", "The certificate chain could not be validated to a trust anchor.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.NoCertificateChainFound);
            }
        }

        // ── Signing certificate ─────────────────────────────────────────────────────

        private void EvaluateSigningCertificate(string path)
        {
            var certificate = facts.SignerCertificate;
            Check(path + "/Recognition", certificate is not null, "The signing certificate was found.", "The signing certificate was not found.",
                SignatureIndication.Indeterminate, SignatureSubIndication.NoSigningCertificateFound);
            if (certificate is null)
            {
                return;
            }

            var time = ReferenceTime;
            if (certificate.NotBefore.ToUniversalTime() > time)
            {
                Check(path + "/NotExpired", false, "", $"The signing certificate is not yet valid at {time:yyyy-MM-dd HH:mm:ss} UTC.",
                    SignatureIndication.Invalid, SignatureSubIndication.NotYetValid);
            }
            else
            {
                Check(path + "/NotExpired", certificate.NotAfter.ToUniversalTime() >= time,
                    "The signing certificate is within its validity period.",
                    $"The signing certificate expired on {certificate.NotAfter.ToUniversalTime():yyyy-MM-dd}, and nothing proves the signature existed before.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.OutOfBoundsNoPoe);
            }

            if (facts.IsCertificateChainValid)
            {
                Check(path + "/Signature", true, "The signature of the signing certificate verifies.", "", SignatureIndication.Indeterminate, SignatureSubIndication.ChainConstraintsFailure);
            }

            CheckCertificateValues(path, certificate);
            CheckCertificateRules(path, certificate, facts.Chain is { Count: > 1 } chain ? chain[1] : null);
            if (SkipsRevocation(path, certificate))
            {
                Check(path + "/RevocationDataAvailable", true, $"'{Name(certificate)}' needs no revocation data.", "",
                    SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
            }
            else
            {
                EvaluateRevocation(path);
                EvaluateRevocationQuality(path, certificate);
            }

            EvaluateCertificateCrypto(path, 0);
        }

        /// <summary>The RFC 5280 checks of one certificate and the subject attributes the policy restricts.</summary>
        private void CheckCertificateRules(string path, X509Certificate2 certificate, X509Certificate2? issuer)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.ChainConstraintsFailure;
            string name = Name(certificate);

            Check(path + "/AuthorityInfoAccessPresent", CertificateChecks.HasExtension(certificate, CertificateChecks.AuthorityInfoAccess),
                $"'{name}' has the Authority Information Access extension.", $"'{name}' has no Authority Information Access extension.", I, S);
            Check(path + "/RevocationInfoAccessPresent", CertificateChecks.HasRevocationInfoAccess(certificate),
                $"'{name}' says where its revocation data is.", $"'{name}' has neither CRL distribution points nor an OCSP location.", I, S);
            Check(path + "/AuthorityKeyIdentifierPresent", CertificateChecks.HasExtension(certificate, CertificateChecks.AuthorityKeyIdentifier),
                $"'{name}' has the Authority Key Identifier extension.", $"'{name}' has no Authority Key Identifier extension.", I, S);
            Check(path + "/SubjectKeyIdentifierPresent", CertificateChecks.HasExtension(certificate, CertificateChecks.SubjectKeyIdentifier),
                $"'{name}' has the Subject Key Identifier extension.", $"'{name}' has no Subject Key Identifier extension.", I, S);
            Check(path + "/SerialNumberPresent", CertificateChecks.HasSubjectSerialNumber(certificate),
                $"The subject of '{name}' has a serialNumber.", $"The subject of '{name}' has no serialNumber.", I, S);
            Check(path + "/NoRevAvail", CertificateChecks.NoRevAvailCompliant(certificate),
                $"'{name}' follows RFC 9608 for noRevAvail.", $"'{name}' has noRevAvail but is a CA or says where its revocation data is (RFC 9608).", I, S);
            if (tree.Find(path + "/ForbiddenExtensions") is { } forbidden)
            {
                var present = CertificateChecks.ForbiddenPresent(certificate, forbidden.Ids).ToList();
                Check(path + "/ForbiddenExtensions", present.Count == 0, $"'{name}' has none of the forbidden extensions.",
                    $"'{name}' has the forbidden extensions {string.Join(", ", present)}.", I, S);
            }

            if (tree.Find(path + "/SupportedCriticalExtensions") is { } supported)
            {
                var unsupported = CertificateChecks.CriticalExtensions(certificate).Where(oid => !supported.Ids.Contains(oid)).ToList();
                Check(path + "/SupportedCriticalExtensions", unsupported.Count == 0, $"Every critical extension of '{name}' is supported.",
                    $"'{name}' has critical extensions that are not supported: {string.Join(", ", unsupported)}.", I, S);
            }

            if (issuer is not null)
            {
                Check(path + "/IssuerName", CertificateChecks.IssuerNameMatches(certificate, issuer),
                    $"The issuer name of '{name}' is its issuer's subject name.", $"The issuer name of '{name}' is not its issuer's subject name.", I, S);
            }

            Check(path + "/UsePseudonym", !CertificateChecks.SubjectValues(certificate, CertificateChecks.SubjectAttributes["Pseudonym"]).Any(),
                $"'{name}' does not use a pseudonym.", $"'{name}' uses a pseudonym.", I, S);
            foreach (var (constraint, oid) in CertificateChecks.SubjectAttributes)
            {
                if (tree.Find(path + "/" + constraint) is { Ids.Count: > 0 } accepted)
                {
                    var values = CertificateChecks.SubjectValues(certificate, oid).ToList();
                    Check(path + "/" + constraint, values.Any(accepted.Ids.Contains),
                        $"The {constraint} of '{name}' is accepted.",
                        values.Count == 0 ? $"'{name}' has no {constraint}." : $"The {constraint} of '{name}' ({string.Join(", ", values)}) is not accepted.", I, S);
                }
            }
        }

        /// <summary>Whether the certificate needs no revocation data (RevocationDataSkip); reports the constraint when it applies.</summary>
        private bool SkipsRevocation(string path, X509Certificate2 certificate)
        {
            string id = path + "/RevocationDataSkip";
            if (tree.Find(id) is null || tree.Level(id) == ConstraintLevel.Ignore)
            {
                return false;
            }

            var extensions = tree.Find(id + "/CertificateExtensions")?.Ids ?? [];
            var policies = tree.Find(id + "/CertificatePolicies")?.Ids ?? [];
            _evaluated.Add(id + "/CertificateExtensions");
            _evaluated.Add(id + "/CertificatePolicies");
            bool skips = CertificateChecks.SkipsRevocation(certificate, extensions, policies);
            Check(id, !skips, $"'{Name(certificate)}' needs revocation data.", $"'{Name(certificate)}' needs no revocation data (RevocationDataSkip).",
                SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
            return skips;
        }

        /// <summary>The chain-wide RFC 5280 checks: path lengths, name constraints and the policy tree.</summary>
        /// <summary>The changes of the later PDF revisions (EN 319 102-1 format checking; ISO 32000 DocMDP and field locks).</summary>
        private void EvaluatePdfChanges(string basic)
        {
            string[] ids = ["PdfPageDifference", "PdfAnnotationOverlap", "DocMDP", "FieldMDP", "SigFieldLock", "FormFillChanges", "AnnotationChanges", "UndefinedChanges"];
            if (facts.PdfChanges is not { } changes)
            {
                foreach (string id in ids)
                {
                    NotApplicable(basic + "/" + id);
                }

                return;
            }

            const SignatureIndication Invalid = SignatureIndication.Invalid;
            const SignatureSubIndication Format = SignatureSubIndication.FormatFailure;
            Check(basic + "/PdfPageDifference", changes.SignedPageCount == changes.FinalPageCount,
                "No page was added or removed after the signature.",
                $"The signed revision has {changes.SignedPageCount} pages, the final one {changes.FinalPageCount}.", Invalid, Format);
            Check(basic + "/PdfAnnotationOverlap", !changes.AnnotationsOverlap, "No annotation added after the signature overlaps another one.",
                "An annotation added after the signature overlaps another one.", Invalid, Format);

            var docMdp = changes.DocMdpViolations;
            Check(basic + "/DocMDP", docMdp.Count == 0,
                changes.DocMdpLevel == 0 ? "The document is not certified (DocMDP)." : $"The later changes are allowed by the certification (DocMDP P={changes.DocMdpLevel}).",
                $"The certification (DocMDP P={changes.DocMdpLevel}) does not allow: {Summary(docMdp)}", Invalid, Format);
            CheckLock(basic + "/FieldMDP", changes.FieldMdp, changes.ChangedFields, "FieldMDP transform");
            CheckLock(basic + "/SigFieldLock", changes.SigFieldLock, changes.ChangedFields, "signature field lock");
            Check(basic + "/FormFillChanges", changes.FormFills.Count == 0, "No form field was filled after the signature.",
                $"Form fields changed after the signature: {Summary(changes.FormFills)}", Invalid, Format);
            Check(basic + "/AnnotationChanges", changes.Annotations.Count == 0, "No annotation changed after the signature.",
                $"Annotations changed after the signature: {Summary(changes.Annotations)}", Invalid, Format);
            Check(basic + "/UndefinedChanges", changes.Undefined.Count == 0, "No other change was made after the signature.",
                $"Other changes after the signature: {Summary(changes.Undefined)}", Invalid, Format);

            void CheckLock(string id, PdfFieldLock? fieldLock, IReadOnlyList<string> changed, string what)
            {
                var locked = fieldLock?.Violations(changed) ?? [];
                Check(id, locked.Count == 0,
                    fieldLock is null ? $"The signature has no {what}." : $"No field locked by the {what} changed.",
                    $"Fields locked by the {what} changed: {string.Join(", ", locked)}.", Invalid, Format);
            }

            static string Summary(IReadOnlyList<string> items) =>
                string.Join(" ", items.Take(5)) + (items.Count > 5 ? $" (and {items.Count - 5} more)" : "");
        }

        private void EvaluateChain(string basic)
        {
            if (facts.Chain is not { Count: > 1 } chain)
            {
                return;
            }

            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.ChainConstraintsFailure;
            bool pathLengths = CertificateChecks.PathLengthsRespected(chain);
            var flags = CertificateChecks.ChainFlags(chain);
            foreach (string path in new[] { basic + "/SigningCertificate", basic + "/CACertificate" })
            {
                Check(path + "/MaxPathLength", pathLengths, "The chain respects the path length constraints.",
                    "A CA of the chain has more CAs below it than its pathLenConstraint allows.", I, S);
                Check(path + "/NameConstraints", CertificateChecks.NameConstraintsRespected(flags), "The chain respects its name constraints.",
                    "A certificate of the chain breaks the name constraints of its CAs.", I, S);
                Check(path + "/PolicyTree", CertificateChecks.PolicyTreeValid(flags), "The certificate policies of the chain form a valid policy tree.",
                    "The certificate policies of the chain do not form a valid policy tree.", I, S);
            }
        }

        private void CheckCertificateValues(string path, X509Certificate2 certificate)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.ChainConstraintsFailure;

            if (tree.Find(path + "/KeyUsage") is { } keyUsage)
            {
                Check(path + "/KeyUsage", CertificateFacts.HasAnyKeyUsage(certificate, keyUsage.Ids),
                    $"The key usage of '{Name(certificate)}' has one of {string.Join(", ", keyUsage.Ids)}.",
                    $"The key usage of '{Name(certificate)}' has none of {string.Join(", ", keyUsage.Ids)}.", I, S);
            }

            if (tree.Find(path + "/ExtendedKeyUsage") is { } extended)
            {
                Check(path + "/ExtendedKeyUsage", CertificateFacts.HasAnyExtendedKeyUsage(certificate, extended.Ids),
                    $"The extended key usage of '{Name(certificate)}' has one of {string.Join(", ", extended.Ids)}.",
                    $"The extended key usage of '{Name(certificate)}' has none of {string.Join(", ", extended.Ids)}.", I, S);
            }

            if (tree.Find(path + "/PolicyIds") is { } policies)
            {
                var present = CertificateFacts.PolicyIds(certificate);
                Check(path + "/PolicyIds", policies.Ids.Count == 0 || policies.Ids.Any(present.Contains),
                    $"'{Name(certificate)}' has one of the certificate policies {string.Join(", ", policies.Ids)}.",
                    $"'{Name(certificate)}' has none of the certificate policies {string.Join(", ", policies.Ids)}.", I, S);
            }

            var statements = CertificateFacts.QcStatements(certificate);
            Check(path + "/QcCompliance", statements.Contains("0.4.0.1862.1.1"),
                $"'{Name(certificate)}' is a qualified certificate (QcCompliance).",
                $"'{Name(certificate)}' has no QcCompliance statement.", I, S);
            Check(path + "/QcSSCD", statements.Contains("0.4.0.1862.1.4"),
                $"The key of '{Name(certificate)}' is on a qualified device (QcSSCD).",
                $"'{Name(certificate)}' has no QcSSCD statement.", I, S);

            bool selfSigned = CertificateFacts.IsSelfSigned(certificate);
            Check(path + "/NotSelfSigned", !selfSigned, $"'{Name(certificate)}' is not self-signed.", $"'{Name(certificate)}' is self-signed.", I, S);
            Check(path + "/SelfSigned", selfSigned, $"'{Name(certificate)}' is self-signed.", $"'{Name(certificate)}' is not self-signed.", I, S);
        }

        private void EvaluateRevocation(string path)
        {
            // No (acceptable) revocation data: the chain cannot be validated (EN 319 102-1 §5.2.6). TRY_LATER is for stale data.
            const SignatureSubIndication NoData = SignatureSubIndication.CertificateChainGeneralFailure;
            switch (facts.IsNotRevoked)
            {
                case null:
                    return;
                case true:
                    Check(path + "/RevocationDataAvailable", true, $"Revocation data was found ({facts.RevocationSource}).", "",
                        SignatureIndication.Indeterminate, NoData);
                    Check(path + "/NotRevoked", true, $"The signing certificate is not revoked ({facts.RevocationSource}).", "",
                        SignatureIndication.Indeterminate, SignatureSubIndication.RevokedNoPoe);
                    break;
                default:
                    if (facts.RevocationSource is RevocationSource.None or RevocationSource.Indeterminate)
                    {
                        Check(path + "/RevocationDataAvailable", false, "", "The revocation status could not be established.",
                            SignatureIndication.Indeterminate, NoData);
                        return;
                    }

                    Check(path + "/RevocationDataAvailable", true, $"Revocation data was found ({facts.RevocationSource}).", "",
                        SignatureIndication.Indeterminate, NoData);
                    EvaluateSignerNotRevoked(path);
                    break;
            }

            if (facts.RevocationIssuedAt is { } issued && tree.Find(path + "/RevocationFreshness") is { Duration: { } maxAge })
            {
                var age = ReferenceTime - issued;
                Check(path + "/RevocationFreshness", age <= maxAge,
                    $"The revocation data was issued {issued:yyyy-MM-dd HH:mm} UTC, within {maxAge}.",
                    $"The revocation data was issued {issued:yyyy-MM-dd HH:mm} UTC, more than {maxAge} before {ReferenceTime:yyyy-MM-dd HH:mm} UTC.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
            }
        }

        /// <summary>
        /// The chain was found revoked: says whether the signing certificate itself is. A revoked certificate is
        /// INDETERMINATE/REVOKED_NO_POE (EN 319 102-1 §5.2.6) unless a proof of existence predates the revocation
        /// (§5.6.2.4); a revoked CA is CACertificate/NotRevoked's (REVOKED_CA_NO_POE).
        /// </summary>
        private void EvaluateSignerNotRevoked(string path)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.RevokedNoPoe;
            var signer = facts.SignerCertificate!;
            if (RevokedAt(signer) is { } revoked)
            {
                Check(path + "/NotRevoked", _proofOfExistence is { } poe && poe < revoked,
                    $"The signing certificate was revoked at {revoked:yyyy-MM-dd HH:mm} UTC, after the signature was proven to exist.",
                    $"The signing certificate is revoked since {revoked:yyyy-MM-dd HH:mm} UTC, and nothing proves the signature existed before ({facts.RevocationSource}).", I, S);
            }
            else if (facts.Chain is { Count: > 1 } chain && chain.Skip(1).Any(ca => RevokedAt(ca) is not null))
            {
                Check(path + "/NotRevoked", true, "The signing certificate is not revoked; a CA of its chain is (CACertificate/NotRevoked).", "", I, S);
            }
            else
            {
                Check(path + "/NotRevoked", false, "", $"The signing certificate is revoked ({facts.RevocationSource}).", I, S);
            }
        }

        /// <summary>When accepted revocation data says <paramref name="certificate"/> was revoked; null when none does.</summary>
        private DateTimeOffset? RevokedAt(X509Certificate2 certificate) =>
            _revocationTokens
                .Where(t => t.Accepted && t.Token.Status == RevocationTokenStatus.Revoked
                    && t.Token.Certificate.RawData.AsSpan().SequenceEqual(certificate.RawData))
                .Select(t => t.Token.RevocationTime ?? DateTimeOffset.MinValue)
                .Cast<DateTimeOffset?>()
                .FirstOrDefault();

        /// <summary>
        /// CACertificate/NotRevoked, from the revocation data about the CA: revoked with no proof of existence before
        /// the revocation is REVOKED_CA_NO_POE. Without data about the CA it is left unevaluated.
        /// </summary>
        private void EvaluateCaNotRevoked(string path, X509Certificate2 ca)
        {
            string name = Name(ca);
            if (RevokedAt(ca) is { } revoked)
            {
                Check(path + "/NotRevoked", _proofOfExistence is { } poe && poe < revoked,
                    $"'{name}' was revoked at {revoked:yyyy-MM-dd HH:mm} UTC, after the signature was proven to exist.",
                    $"'{name}' is revoked since {revoked:yyyy-MM-dd HH:mm} UTC, and nothing proves the signature existed before.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.RevokedCaNoPoe);
            }
            else if (_revocationTokens.Any(t => t.Accepted && t.Token.Status == RevocationTokenStatus.Good
                && t.Token.Certificate.RawData.AsSpan().SequenceEqual(ca.RawData)))
            {
                Check(path + "/NotRevoked", true, $"'{name}' is not revoked.", "", SignatureIndication.Indeterminate, SignatureSubIndication.RevokedCaNoPoe);
            }
        }

        // ── CA certificates and the model ────────────────────────────────────────────

        private void EvaluateCaCertificates(string path)
        {
            if (facts.Chain is not { Count: > 1 } chain)
            {
                return;
            }

            string model = tree.Find("Model")?.Value ?? "SHELL";
            for (int i = 1; i < chain.Count; i++)
            {
                var ca = chain[i];
                // Shell: every certificate at the reference time. Chain and hybrid: a CA when it issued its subordinate.
                var time = model is "CHAIN" or "HYBRID" ? chain[i - 1].NotBefore.ToUniversalTime() : ReferenceTime;
                bool valid = ca.NotBefore.ToUniversalTime() <= time && ca.NotAfter.ToUniversalTime() >= time;
                Check(path + "/NotExpired", valid,
                    $"'{Name(ca)}' is within its validity period ({model}).",
                    $"'{Name(ca)}' is not valid at {time:yyyy-MM-dd HH:mm:ss} UTC ({model} model).",
                    SignatureIndication.Indeterminate, SignatureSubIndication.OutOfBoundsNoPoe);
                Check(path + "/CA", CertificateFacts.IsCa(ca), $"'{Name(ca)}' is a CA.", $"'{Name(ca)}' is not a CA (basic constraints).",
                    SignatureIndication.Indeterminate, SignatureSubIndication.ChainConstraintsFailure);
                if (tree.Find(path + "/KeyUsage") is { } keyUsage)
                {
                    Check(path + "/KeyUsage", CertificateFacts.HasAnyKeyUsage(ca, keyUsage.Ids),
                        $"The key usage of '{Name(ca)}' has one of {string.Join(", ", keyUsage.Ids)}.",
                        $"The key usage of '{Name(ca)}' has none of {string.Join(", ", keyUsage.Ids)}.",
                        SignatureIndication.Indeterminate, SignatureSubIndication.ChainConstraintsFailure);
                }

                if (facts.IsCertificateChainValid)
                {
                    Check(path + "/Signature", true, $"The signature of '{Name(ca)}' verifies.", "", SignatureIndication.Indeterminate, SignatureSubIndication.ChainConstraintsFailure);
                }

                CheckCertificateRules(path, ca, i + 1 < chain.Count ? chain[i + 1] : null);
                if (i + 1 < chain.Count)
                {
                    EvaluateRevocationQuality(path, ca);
                    EvaluateCaNotRevoked(path, ca);
                }
                EvaluateCertificateCrypto(path, i);
            }
        }

        // ── Cryptographic constraints ───────────────────────────────────────────────

        /// <summary>The signature itself: its digest algorithm and the signing key, at the time the signature is proven to exist.</summary>
        private void EvaluateSignatureCrypto(string basic)
        {
            var rules = tree.Crypto(basic);
            string id = basic + "/Cryptographic";
            var findings = new List<CryptoFinding>();
            if (facts.DigestAlgorithmOid is { } digest)
            {
                findings.AddRange(rules.CheckDigest(CryptographicRules.DigestName(digest), ReferenceTime));
            }

            bool pss = facts.SignatureAlgorithmOid == Constants.Oids.RsaPss;
            if (facts.SignerCertificate is { } signer && CryptographicRules.KeyOf(signer, pss) is { } key)
            {
                findings.AddRange(rules.CheckKey(key.Algorithm, key.Size, ReferenceTime));
            }

            RecordCrypto(id, rules, findings, "The signature's algorithms are accepted.");
        }

        /// <summary>The signature of the certificate at <paramref name="index"/> of the chain: its digest and its issuer's key.</summary>
        private void EvaluateCertificateCrypto(string path, int index)
        {
            if (facts.Chain is not { } chain || index >= chain.Count || CertificateFacts.IsSelfSigned(chain[index]))
            {
                return; // A trust anchor's own signature is not checked.
            }

            var certificate = chain[index];
            var rules = tree.Crypto(path);
            var findings = new List<CryptoFinding>();
            var algorithm = CryptographicRules.SignatureAlgorithmOf(certificate);
            // A certificate exists from its issuance: its own notBefore is the time its algorithms are judged at.
            var time = certificate.NotBefore.ToUniversalTime() < ReferenceTime ? certificate.NotBefore.ToUniversalTime() : ReferenceTime;
            if (algorithm is not null)
            {
                findings.AddRange(rules.CheckDigest(algorithm.Value.Digest, time));
            }

            if (index + 1 < chain.Count && CryptographicRules.KeyOf(chain[index + 1], algorithm?.Pss == true) is { } issuerKey)
            {
                findings.AddRange(rules.CheckKey(issuerKey.Algorithm, issuerKey.Size, time));
            }

            RecordCrypto(path + "/Cryptographic", rules, findings, $"The algorithms of the signature of '{Name(certificate)}' are accepted.");
        }

        private void RecordCrypto(string id, CryptographicRules rules, List<CryptoFinding> findings, string passed)
        {
            if (rules.Level == ConstraintLevel.Ignore)
            {
                return;
            }

            _evaluated.Add(id);
            if (findings.Count == 0)
            {
                _constraints.Add(new(id, ConstraintStatus.Passed, null, Labeled(passed)));
                return;
            }

            foreach (var finding in findings)
            {
                Record(id + "/" + finding.Id, finding.Level, finding.Message, SignatureIndication.Indeterminate,
                    finding.IsExpiry ? SignatureSubIndication.CryptoConstraintsFailureNoPoe : SignatureSubIndication.CryptoConstraintsFailure);
            }
        }

        // ── Signature constraints and signed attributes ────────────────────────────────

        private void EvaluateSignatureConstraints()
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.SigConstraintsFailure;
            if (tree.Find(SignatureContext + "/AcceptableFormats") is { } formats)
            {
                if (facts.SignatureFormat is { } format)
                {
                    Check(SignatureContext + "/AcceptableFormats", formats.Ids.Count == 0 || formats.Ids.Contains("*") || formats.Ids.Contains(format),
                        $"The format {format} is accepted.", $"The format {format} is not accepted ({string.Join(", ", formats.Ids)}).", I, SignatureSubIndication.FormatFailure);
                }
                else
                {
                    NotApplicable(SignatureContext + "/AcceptableFormats");
                }
            }

            Fact(SignatureContext + "/StructuralValidation", facts.StructureErrors is { } structure ? structure.Count == 0 : null,
                "The signature's structure is valid.",
                $"The signature's structure is not valid: {string.Join(" ", facts.StructureErrors?.Take(3) ?? [])}",
                SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);
            Fact(SignatureContext + "/FullScope", facts.CoversWholeDocument, "The signature covers the whole document.",
                "The signature covers only part of the document (later changes are not signed).", I, S);
            Fact(SignatureContext + "/SignaturePolicyStorePresent", facts.PolicyStorePresent, "The signature carries its signature policy document.",
                "The signature does not carry its signature policy document.", I, S);
            if (facts.SignaturePolicyOid is null)
            {
                NotApplicable(SignatureContext + "/PolicyAvailable");
            }
            else
            {
                Fact(SignatureContext + "/PolicyAvailable", facts.PolicyDocumentAvailable, "The signature policy document was obtained.",
                    "The signature policy document could not be obtained.", I, SignatureSubIndication.SignaturePolicyNotAvailable);
            }

            if (!facts.SignaturePolicyKnown)
            {
                return;
            }

            if (tree.Find(SignatureContext + "/AcceptablePolicies") is { } acceptable)
            {
                string? oid = facts.SignaturePolicyOid;
                bool accepted = oid is null
                    ? acceptable.Ids.Contains("NO_POLICY")
                    : acceptable.Ids.Contains("ANY_POLICY") || acceptable.Ids.Contains(oid);
                Check(SignatureContext + "/AcceptablePolicies", accepted,
                    oid is null ? "The signature names no signature policy, which is accepted." : $"The signature policy {oid} is accepted.",
                    oid is null ? "The signature names no signature policy, and the policy requires one." : $"The signature policy {oid} is not accepted.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.SigConstraintsFailure);
            }

            if (facts.PolicyHashMatches is { } matches)
            {
                Check(SignatureContext + "/PolicyHashMatch", matches, "The signature policy's hash matches.", "The signature policy's hash does not match.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.SigConstraintsFailure);
            }
        }

        private void EvaluateSignedAttributes(string path)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.SigConstraintsFailure;

            if (facts.SigningTimeKnown)
            {
                Check(path + "/SigningTime", facts.ClaimedSigningTime is not null, "The signature claims a signing time.", "The signature claims no signing time.", I, S);
                if (facts.ClaimedSigningTime is { } claimed && facts.SignerCertificate is { } signer)
                {
                    Check(path + "/SigningTimeInCertRange",
                        claimed >= signer.NotBefore.ToUniversalTime() && claimed <= signer.NotAfter.ToUniversalTime(),
                        "The claimed signing time is within the validity of the signing certificate.",
                        $"The claimed signing time {claimed:yyyy-MM-dd HH:mm:ss} UTC is outside the validity of the signing certificate.", I, S);
                }
            }

            if (facts.HasSigningCertificateReference is { } present)
            {
                Check(path + "/SigningCertificatePresent", present, "The signature references its signing certificate.",
                    "The signature does not reference its signing certificate.", I, S);
                Check(path + "/CertDigestPresent", present, "The reference carries the certificate's digest.",
                    "The signature carries no digest of its signing certificate.", I, S);
            }

            if (facts.SigningCertificateReferenceMatches is { } match)
            {
                Check(path + "/CertDigestMatch", match, "The certificate digest in the signature matches the signing certificate.",
                    "The certificate digest in the signature does not match the signing certificate.", I, S);
            }

            if (facts.SignedAttributes is not { } attributes)
            {
                return;
            }

            Check(path + "/MessageDigestOrSignedPropertiesPresent", attributes.MessageDigestOrSignedPropertiesPresent,
                "The message-digest attribute (or the SignedProperties) is present.", "The message-digest attribute (or the SignedProperties) is missing.",
                SignatureIndication.Invalid, SignatureSubIndication.FormatFailure);
            if (attributes.SigningCertificateAttributes > 0)
            {
                Check(path + "/UnicitySigningCertificate", attributes.SigningCertificateAttributes == 1, "There is one signing-certificate attribute.",
                    $"There are {attributes.SigningCertificateAttributes} signing-certificate attributes.", I, S);
            }

            EvaluateCertificateReferences(path, attributes.CertificateReferences);
            CheckValues(path + "/ContentType", attributes.ContentType is { } type ? [type] : [], "content type");
            CheckValues(path + "/ContentHints", attributes.ContentHints is { } hints ? [hints] : [], "content hints");
            CheckValues(path + "/ContentIdentifier", attributes.ContentIdentifier is { } identifier ? [identifier] : [], "content identifier");
            CheckValues(path + "/CommitmentTypeIndication", attributes.CommitmentTypes, "commitment type");
            CheckValues(path + "/ClaimedRoles", attributes.ClaimedRoles, "claimed role");
            Check(path + "/SignerLocation", attributes.SignerLocation, "The signature has a signer location.", "The signature has no signer location.", I, S);
            Check(path + "/ContentTimeStamp", attributes.ContentTimestamp, "The signature has a content timestamp.", "The signature has no content timestamp.", I, S);
            if (attributes.ContentTimestamp)
            {
                var content = facts.Timestamps?.FirstOrDefault(t => t.Kind == TimestampTokenKind.Content);
                Fact(path + "/ContentTimeStampMessageImprint", content?.ImprintValid, "The content timestamp covers the signed data.",
                    "The content timestamp does not cover the signed data.", SignatureIndication.Invalid, SignatureSubIndication.HashFailure);
            }
            else
            {
                NotApplicable(path + "/ContentTimeStampMessageImprint");
            }

            // Certified roles are matched by presence: the role names inside attribute certificates are not read.
            Check(path + "/CertifiedRoles", attributes.CertifiedRoles > 0, $"The signature has {attributes.CertifiedRoles} certified role(s).",
                "The signature has no certified role.", I, S);
        }

        /// <summary>The signing certificate references: digest algorithm, issuer and serial, and how they cover the chain.</summary>
        private void EvaluateCertificateReferences(string path, IReadOnlyList<CertificateReference> references)
        {
            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.SigConstraintsFailure;
            if (references.Count == 0 || facts.SignerCertificate is not { } signer)
            {
                return;
            }

            var own = references.FirstOrDefault(r => r.DigestMatches(signer)) ?? references[0];
            var rules = tree.Crypto(path);
            var findings = rules.CheckDigest(own.DigestAlgorithm, ReferenceTime);
            Check(path + "/SigningCertificateDigestAlgorithm", findings.All(f => f.Level != ConstraintLevel.Fail),
                $"The signing certificate reference uses {own.DigestAlgorithm}, which is accepted.",
                $"The signing certificate reference uses {own.DigestAlgorithm}, which is not accepted.", I, SignatureSubIndication.CryptoConstraintsFailure);
            if (own.IssuerSerialMatches(signer) is { } issuerSerial)
            {
                Check(path + "/IssuerSerialMatch", issuerSerial, "The issuer and serial number of the reference match the signing certificate.",
                    "The issuer and serial number of the reference do not match the signing certificate.", I, S);
            }

            if (facts.Chain is { Count: > 0 } chain)
            {
                Check(path + "/SigningCertificateRefersCertificateChain", references.All(r => chain.Any(r.DigestMatches)),
                    "Every certificate reference designates a certificate of the chain.", "A certificate reference designates no certificate of the chain.", I, S);
                var notReferenced = chain.Where(c => !CertificateFacts.IsSelfSigned(c) && !references.Any(r => r.DigestMatches(c))).ToList();
                Check(path + "/ReferencesToAllCertificateChainPresent", notReferenced.Count == 0,
                    "Every certificate of the chain is referenced.", $"{notReferenced.Count} certificate(s) of the chain are not referenced.", I, S);
            }
        }

        /// <summary>A multi-value constraint on attribute values: one of the policy's values (or any, with <c>*</c>) must be present.</summary>
        private void CheckValues(string id, IReadOnlyList<string> values, string what)
        {
            if (tree.Find(id) is not { } accepted)
            {
                return;
            }

            bool any = accepted.Ids.Count == 0 || accepted.Ids.Contains("*");
            Check(id, values.Count > 0 && (any || values.Any(accepted.Ids.Contains)),
                $"The {what} ({string.Join(", ", values)}) is accepted.",
                values.Count == 0 ? $"The signature has no {what}." : $"The {what} ({string.Join(", ", values)}) is not accepted.",
                SignatureIndication.Indeterminate, SignatureSubIndication.SigConstraintsFailure);
        }

        private void EvaluateUnsignedAttributes(string path)
        {
            if (facts.UnsignedAttributes is not { } unsigned)
            {
                return;
            }

            const SignatureIndication I = SignatureIndication.Indeterminate;
            const SignatureSubIndication S = SignatureSubIndication.SigConstraintsFailure;
            Check(path + "/CounterSignature", unsigned.CounterSignature, "The signature has a countersignature.", "The signature has no countersignature.", I, S);
            Check(path + "/SignatureTimeStamp", unsigned.SignatureTimeStamp, "The signature has a signature timestamp.", "The signature has no signature timestamp.", I, S);
            Check(path + "/ValidationDataTimeStamp", unsigned.ValidationDataTimeStamp, "The signature has a timestamp over its validation data.",
                "The signature has no timestamp over its validation data.", I, S);
            Check(path + "/ValidationDataRefsOnlyTimeStamp", unsigned.ValidationDataRefsOnlyTimeStamp,
                "The signature has a timestamp over the references to its validation data.", "The signature has no timestamp over the references to its validation data.", I, S);
            Check(path + "/ArchiveTimeStamp", unsigned.ArchiveTimeStamp, "The signature has an archive timestamp.", "The signature has no archive timestamp.", I, S);
            Check(path + "/DocumentTimeStamp", unsigned.DocumentTimeStamp, "The document has a document timestamp.", "The document has no document timestamp.", I, S);
            Fact(path + "/TLevelTimeStamp", unsigned.TLevelTimeStampValid, "A valid T-level timestamp is present.", "No valid T-level timestamp is present.", I, S);
            Fact(path + "/LTALevelTimeStamp", unsigned.LtaLevelTimeStampValid, "A valid LTA-level timestamp is present.", "No valid LTA-level timestamp is present.", I, S);
        }

        private void EvaluateTimestampDelay()
        {
            if (facts.ClaimedSigningTime is { } claimed && _proofOfExistence is { } timestamp
                && tree.Find(Timestamp + "/TimestampDelay") is { Duration: { } delay })
            {
                Check(Timestamp + "/TimestampDelay", timestamp - claimed <= delay,
                    $"The signature timestamp is within {delay} of the claimed signing time.",
                    $"The signature timestamp is more than {delay} after the claimed signing time.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.SigConstraintsFailure);
            }
        }

        /// <summary>The type and status, in its trusted list, of the trust service the chain's anchor belongs to.</summary>
        private void EvaluateTrustService(string basic)
        {
            var service = facts.Chain is { Count: > 0 } chain && facts.TrustedLists is { } lists
                ? lists.SelectMany(l => l.Services).FirstOrDefault(s => s.Certificates.Any(a => chain.Any(c => c.RawData.AsSpan().SequenceEqual(a.RawData))))
                : null;
            if (service is null)
            {
                NotApplicable(basic + "/TrustServiceTypeIdentifier");
                NotApplicable(basic + "/TrustServiceStatus");
                return;
            }

            static bool Matches(IReadOnlyList<string> accepted, string uri) =>
                accepted.Count == 0 || accepted.Any(a => uri == a || uri.EndsWith(a, StringComparison.Ordinal));
            if (tree.Find(basic + "/TrustServiceTypeIdentifier") is { } types)
            {
                Check(basic + "/TrustServiceTypeIdentifier", Matches(types.Ids, service.ServiceType), $"The trust service type {service.ServiceType} is accepted.",
                    $"The trust service type {service.ServiceType} is not accepted.", SignatureIndication.Indeterminate, SignatureSubIndication.ChainConstraintsFailure);
            }

            if (tree.Find(basic + "/TrustServiceStatus") is { } statuses)
            {
                Check(basic + "/TrustServiceStatus", Matches(statuses.Ids, service.Status), $"The trust service status {service.Status} is accepted.",
                    $"The trust service status {service.Status} is not accepted.", SignatureIndication.Indeterminate, SignatureSubIndication.ChainConstraintsFailure);
            }
        }

        // ── TrustedLists: the trusted list the chain's anchor comes from ─────────────────────────

        /// <summary>Evaluates the TrustedLists constraints for the trusted list that holds a certificate of the chain; false when none does.</summary>
        private bool EvaluateTrustedList()
        {
            if (facts.TrustedLists is not { Count: > 0 } lists || facts.Chain is not { Count: > 0 } chain)
            {
                return false;
            }

            var list = lists.FirstOrDefault(l => l.Anchors.Any(a => chain.Any(c => c.RawData.AsSpan().SequenceEqual(a.RawData))));
            if (list is null)
            {
                return false;
            }

            const SignatureIndication I = SignatureIndication.Indeterminate;
            string name = $"The trusted list {list.Territory}";
            if (tree.Find("TrustedLists/TLFreshness") is { Duration: { } freshness })
            {
                Check("TrustedLists/TLFreshness", facts.ValidationTime - list.LoadedAt <= freshness,
                    $"{name} was loaded {list.LoadedAt:yyyy-MM-dd HH:mm} UTC, within {freshness}.",
                    $"{name} was loaded {list.LoadedAt:yyyy-MM-dd HH:mm} UTC, more than {freshness} ago.", I, SignatureSubIndication.TryLater);
            }

            Check("TrustedLists/TLNotExpired", list.NextUpdate is not { } next || next >= facts.ValidationTime,
                $"{name} has not expired.", $"{name} expired: its NextUpdate was {list.NextUpdate:yyyy-MM-dd HH:mm} UTC.", I, SignatureSubIndication.TryLater);
            Check("TrustedLists/TLWellSigned", list.IsWellSigned, $"{name} is signed by its scheme operator.",
                $"{name} is not signed by its scheme operator.", I, SignatureSubIndication.NoCertificateChainFound);
            Fact("TrustedLists/TLStructure", list.IsStructureValid, $"{name} is valid against the TS 119 612 schema.",
                $"{name} is not valid against the TS 119 612 schema.", I, SignatureSubIndication.NoCertificateChainFound);
            if (tree.Find("TrustedLists/TLVersion") is { } version)
            {
                Check("TrustedLists/TLVersion", version.Ids.Count == 0 || (list.Version is not null && version.Ids.Contains(list.Version)),
                    $"{name} has version {list.Version}.", $"{name} has version {list.Version ?? "(none)"}; the policy accepts {string.Join(", ", version.Ids)}.",
                    I, SignatureSubIndication.NoCertificateChainFound);
            }

            return true;
        }

        // ── Recording ──────────────────────────────────────────────────────────────

        /// <summary>Evaluates the constraint at <paramref name="id"/> with its level from the policy; absent or IGNORE skips it.</summary>
        private void Check(string id, bool passed, string passedMessage, string failedMessage, SignatureIndication indication, SignatureSubIndication sub)
        {
            var level = tree.Level(id);
            if (level == ConstraintLevel.Ignore)
            {
                return;
            }

            if (passed)
            {
                if (_evaluated.Add(id) || Nested)
                {
                    _constraints.Add(new(id, ConstraintStatus.Passed, null, Labeled(passedMessage)));
                }

                return;
            }

            Record(id, level, failedMessage, indication, sub);
        }

        /// <summary>A constraint whose fact may be unknown: null means it does not apply to this signature (it is then not reported).</summary>
        private void Fact(string id, bool? passed, string passedMessage, string failedMessage, SignatureIndication indication, SignatureSubIndication sub)
        {
            if (passed is { } value)
            {
                Check(id, value, passedMessage, failedMessage, indication, sub);
            }
            else
            {
                NotApplicable(id);
            }
        }

        /// <summary>A constraint that does not apply to this signature (a PDF check on a CMS file, say): not reported, not "not checked".</summary>
        private void NotApplicable(string id) => _evaluated.Add(id);

        /// <summary>A message of a nested evaluation names its token.</summary>
        private string Labeled(string message) => label is null ? message : $"[{label}] {message}";

        private void Record(string id, ConstraintLevel level, string message, SignatureIndication indication, SignatureSubIndication sub)
        {
            _evaluated.Add(id);
            message = Labeled(message);
            switch (level)
            {
                case ConstraintLevel.Fail:
                    _constraints.Add(new(id, ConstraintStatus.Failed, sub, message));
                    Decide(indication, sub);
                    break;
                case ConstraintLevel.Warn:
                    _constraints.Add(new(id, ConstraintStatus.Warning, sub, message));
                    _warnings.Add(message);
                    break;
                case ConstraintLevel.Inform:
                    _constraints.Add(new(id, ConstraintStatus.Information, sub, message));
                    break;
                default:
                    break;
            }
        }

        private void Decide(SignatureIndication indication, SignatureSubIndication? sub) => _decided ??= (indication, sub);

        /// <summary>Lists the constraints of <paramref name="context"/> with a level that SimpleSign did not evaluate.</summary>
        private void ReportNotEvaluated(string context)
        {
            if (tree.Root.Find(context) is not { } node)
            {
                return;
            }

            foreach (var (path, leaf) in Leaves(node, context))
            {
                if (leaf.Level is { } level && level != ConstraintLevel.Ignore && !_evaluated.Contains(path))
                {
                    _constraints.Add(new(path, ConstraintStatus.NotChecked, null,
                        PolicyCoverage.Validation(path) == ConstraintCoverage.ToImplement
                            ? "Not evaluated by SimpleSign: it needs work not done yet."
                            : "Not evaluated by SimpleSign yet."));
                }
            }
        }

        private static IEnumerable<(string Path, PolicyNode Node)> Leaves(PolicyNode node, string path)
        {
            foreach (var child in node.Children)
            {
                string childPath = path + "/" + child.Name;
                if (child.Type is "CryptographicConstraint" or "String")
                {
                    continue; // Cryptographic constraints are evaluated per token above.
                }

                if (child.Children.Count > 0 && child.Type is not "CertificateValuesConstraint")
                {
                    foreach (var leaf in Leaves(child, childPath))
                    {
                        yield return leaf;
                    }
                }
                else
                {
                    yield return (childPath, child);
                }
            }
        }

        private static string Name(X509Certificate2 certificate) => certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
    }

    /// <summary>The policy name of a digest algorithm OID.</summary>
    internal static string DigestName(string oid) => CryptographicRules.DigestName(oid);
}

/// <summary>Adds to <see cref="ValidationFacts"/> what a CMS signature (CAdES, PAdES) tells about the policy's constraints.</summary>
internal static class CmsValidationFacts
{
    /// <summary>
    /// The facts with the chain (built from the signature's certificates and <paramref name="extraCertificates"/>, no
    /// download), the signature algorithm, the signing time, the signing certificate reference and the signature policy.
    /// </summary>
    internal static ValidationFacts WithCms(
        this ValidationFacts facts,
        Crypto.CmsSignedData cms,
        IEnumerable<X509Certificate2>? extraCertificates = null,
        DateTimeOffset? fallbackSigningTime = null)
    {
        IReadOnlyList<X509Certificate2>? chain = null;
        if (cms.SignerCertificate is { } signer)
        {
            var candidates = cms.Certificates.Concat(extraCertificates ?? []).ToList();
            chain = Signing.SignerAcceptance.OrderChain(signer, candidates);
        }

        bool? matches = null;
        if (cms.SigningCertificateHash is { } hash && cms.SignerCertificate is { } certificate)
        {
            string digest = CryptographicRules.DigestName(cms.SigningCertificateHashAlgorithmOid ?? "1.3.14.3.2.26");
            var algorithm = digest switch
            {
                "SHA1" => System.Security.Cryptography.HashAlgorithmName.SHA1,
                "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
                "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
                "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
                _ => (System.Security.Cryptography.HashAlgorithmName?)null,
            };
            if (algorithm is { } name)
            {
                // ESS signing-certificate (v1) references are SHA-1 by definition (RFC 2634 §5.4).
                using var hasher = System.Security.Cryptography.IncrementalHash.CreateHash(name);
                hasher.AppendData(certificate.RawData);
                matches = hasher.GetHashAndReset().AsSpan().SequenceEqual(hash);
            }
        }

        return facts with
        {
            // The CMS was decoded (ASN.1 well formed, SignedData read): its structure is valid.
            StructureErrors = facts.StructureErrors ?? [],
            Chain = chain,
            SignatureAlgorithmOid = cms.SignatureAlgorithmOid,
            ClaimedSigningTime = cms.SigningTime ?? fallbackSigningTime,
            SigningTimeKnown = true,
            HasSigningCertificateReference = cms.SignedAttrs is null ? null : cms.SigningCertificateHash is not null,
            SigningCertificateReferenceMatches = matches,
            SignaturePolicyOid = cms.SignaturePolicyOid,
            SignaturePolicyKnown = true,
            SignedAttributes = SignedAttributeFacts.FromCms(cms.SignedAttrs),
            UnsignedAttributes = facts.UnsignedAttributes ?? UnsignedOf(cms),
            PolicyStorePresent = cms.SignaturePolicyOid is null ? null : HasUnsigned(cms, Constants.Oids.SignaturePolicyStore),
            PolicyDocumentAvailable = facts.PolicyDocumentAvailable
                ?? (cms.SignaturePolicyOid is not null && HasUnsigned(cms, Constants.Oids.SignaturePolicyStore) ? true : null),
        };
    }

    /// <summary>The unsigned attributes of a CMS signature (the validity of the timestamps is the validator's to add).</summary>
    internal static UnsignedAttributeFacts UnsignedOf(Crypto.CmsSignedData cms) => new()
    {
        CounterSignature = cms.CounterSignatures.Count > 0 || HasUnsigned(cms, Constants.Oids.CounterSignature),
        SignatureTimeStamp = cms.SignatureTimestampToken is not null,
        ValidationDataTimeStamp = HasUnsigned(cms, Constants.Oids.EscTimeStamp),
        ValidationDataRefsOnlyTimeStamp = HasUnsigned(cms, "1.2.840.113549.1.9.16.2.26"),
        ArchiveTimeStamp = cms.ArchiveTimestampToken is not null || HasUnsigned(cms, Constants.Oids.ArchiveTimeStamp)
            || HasUnsigned(cms, Constants.Oids.ArchiveTimeStampV3),
    };

    private static bool HasUnsigned(Crypto.CmsSignedData cms, string oid) => cms.UnsignedAttributes?.ContainsKey(oid) == true;
}
