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

    /// <summary>Whether no other element of the document has the signature's Id (XAdES); null for other formats.</summary>
    public bool? SignatureIdUnique { get; init; }
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

    internal static ValidationEvaluation Evaluate(ValidationFacts facts, ValidationPolicy policy) =>
        new Evaluation(facts, policy.Tree).Run() with { Policy = AppliedPolicy.Of(policy) };

    /// <summary>One evaluation: the facts, the policy and what was found so far.</summary>
    private sealed class Evaluation(ValidationFacts facts, PolicyTree tree)
    {
        private readonly List<ValidationConstraintResult> _constraints = [];
        private readonly List<string> _warnings = [];
        private readonly HashSet<string> _evaluated = new(StringComparer.Ordinal);
        private (SignatureIndication Indication, SignatureSubIndication? Sub)? _decided;

        private DateTimeOffset ReferenceTime => facts.ProofOfExistence ?? facts.ValidationTime;

        public ValidationEvaluation Run()
        {
            // A document timestamp is a timestamp token: the Timestamp constraints apply to it.
            string context = facts.IsDocumentTimestamp ? Timestamp : Signature;
            string basic = context + "/BasicSignatureConstraints";

            EvaluateBasic(basic);
            EvaluateSigningCertificate(basic + "/SigningCertificate");
            EvaluateCaCertificates(basic + "/CACertificate");
            EvaluateSignatureCrypto(basic);
            EvaluateChain(basic);
            if (!facts.IsDocumentTimestamp)
            {
                EvaluateSignatureConstraints();
                EvaluateSignedAttributes(Signature + "/SignedAttributes");
                EvaluateUnsignedAttributes(Signature + "/UnsignedAttributes");
                EvaluateTimestampDelay();
            }

            ReportNotEvaluated(context);
            if (EvaluateTrustedList())
            {
                ReportNotEvaluated("TrustedLists");
            }

            var outcome = _decided ?? (SignatureIndication.Valid, null);
            return new ValidationEvaluation(outcome.Indication, outcome.Sub, _constraints, _warnings);
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
            switch (facts.IsNotRevoked)
            {
                case null:
                    return;
                case true:
                    Check(path + "/RevocationDataAvailable", true, $"Revocation data was found ({facts.RevocationSource}).", "",
                        SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
                    Check(path + "/NotRevoked", true, $"The signing certificate is not revoked ({facts.RevocationSource}).", "",
                        SignatureIndication.Invalid, SignatureSubIndication.Revoked);
                    break;
                default:
                    if (facts.RevocationSource is RevocationSource.None or RevocationSource.Indeterminate)
                    {
                        Check(path + "/RevocationDataAvailable", false, "", "The revocation status could not be established.",
                            SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
                        return;
                    }

                    Check(path + "/RevocationDataAvailable", true, $"Revocation data was found ({facts.RevocationSource}).", "",
                        SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
                    Check(path + "/NotRevoked", false, "", $"The signing certificate is revoked ({facts.RevocationSource}).",
                        SignatureIndication.Invalid, SignatureSubIndication.Revoked);
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
                _constraints.Add(new(id, ConstraintStatus.Passed, null, passed));
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
            if (tree.Find(Signature + "/AcceptableFormats") is { } formats)
            {
                if (facts.SignatureFormat is { } format)
                {
                    Check(Signature + "/AcceptableFormats", formats.Ids.Count == 0 || formats.Ids.Contains("*") || formats.Ids.Contains(format),
                        $"The format {format} is accepted.", $"The format {format} is not accepted ({string.Join(", ", formats.Ids)}).", I, SignatureSubIndication.FormatFailure);
                }
                else
                {
                    NotApplicable(Signature + "/AcceptableFormats");
                }
            }

            Fact(Signature + "/FullScope", facts.CoversWholeDocument, "The signature covers the whole document.",
                "The signature covers only part of the document (later changes are not signed).", I, S);
            Fact(Signature + "/SignaturePolicyStorePresent", facts.PolicyStorePresent, "The signature carries its signature policy document.",
                "The signature does not carry its signature policy document.", I, S);
            if (facts.SignaturePolicyOid is null)
            {
                NotApplicable(Signature + "/PolicyAvailable");
            }
            else
            {
                Fact(Signature + "/PolicyAvailable", facts.PolicyDocumentAvailable, "The signature policy document was obtained.",
                    "The signature policy document could not be obtained.", I, SignatureSubIndication.SignaturePolicyNotAvailable);
            }

            if (!facts.SignaturePolicyKnown)
            {
                return;
            }

            if (tree.Find(Signature + "/AcceptablePolicies") is { } acceptable)
            {
                string? oid = facts.SignaturePolicyOid;
                bool accepted = oid is null
                    ? acceptable.Ids.Contains("NO_POLICY")
                    : acceptable.Ids.Contains("ANY_POLICY") || acceptable.Ids.Contains(oid);
                Check(Signature + "/AcceptablePolicies", accepted,
                    oid is null ? "The signature names no signature policy, which is accepted." : $"The signature policy {oid} is accepted.",
                    oid is null ? "The signature names no signature policy, and the policy requires one." : $"The signature policy {oid} is not accepted.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.SigConstraintsFailure);
            }

            if (facts.PolicyHashMatches is { } matches)
            {
                Check(Signature + "/PolicyHashMatch", matches, "The signature policy's hash matches.", "The signature policy's hash does not match.",
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
            if (facts.ClaimedSigningTime is { } claimed && facts.ProofOfExistence is { } timestamp
                && tree.Find(Timestamp + "/TimestampDelay") is { Duration: { } delay })
            {
                Check(Timestamp + "/TimestampDelay", timestamp - claimed <= delay,
                    $"The signature timestamp is within {delay} of the claimed signing time.",
                    $"The signature timestamp is more than {delay} after the claimed signing time.",
                    SignatureIndication.Indeterminate, SignatureSubIndication.SigConstraintsFailure);
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
                if (_evaluated.Add(id))
                {
                    _constraints.Add(new(id, ConstraintStatus.Passed, null, passedMessage));
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

        private void Record(string id, ConstraintLevel level, string message, SignatureIndication indication, SignatureSubIndication sub)
        {
            _evaluated.Add(id);
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
