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

    /// <summary>The trusted lists the trust anchors come from, for the eIDAS constraints; null when none.</summary>
    public IReadOnlyList<Extensions.TrustedListInfo>? TrustedLists { get; init; }
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
/// Turns the facts of a validation into an ETSI EN 319 102-1 outcome under a <see cref="ValidationPolicy"/> in the
/// structure of the EU DSS policy: each constraint of the policy that applies is evaluated with its level and reported
/// with its path as id; the first FAIL decides the indication and sub-indication. Constraints of the policy that
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
            if (!facts.IsDocumentTimestamp)
            {
                EvaluateSignatureConstraints();
                EvaluateSignedAttributes(Signature + "/SignedAttributes");
                EvaluateTimestampDelay();
            }

            ReportNotEvaluated(context);
            if (EvaluateTrustedList())
            {
                ReportNotEvaluated("eIDAS");
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

            // Document timestamps whose chain is only a warning need a trusted TSA.
            if (facts.IsDocumentTimestamp && facts.IsChainTrustWarning && facts.IsTsaTrusted != true)
            {
                Decide(SignatureIndication.Indeterminate, SignatureSubIndication.NoCertificateChainFound);
            }

            string chain = basic + "/ProspectiveCertificateChain";
            if (facts.IsCertificateChainValid)
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
            EvaluateRevocation(path);
            EvaluateCertificateCrypto(path, 0);
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

        // ── eIDAS: the trusted list the chain's anchor comes from ─────────────────────────

        /// <summary>Evaluates the eIDAS constraints for the trusted list that holds a certificate of the chain; false when none does.</summary>
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
            if (tree.Find("eIDAS/TLFreshness") is { Duration: { } freshness })
            {
                Check("eIDAS/TLFreshness", facts.ValidationTime - list.LoadedAt <= freshness,
                    $"{name} was loaded {list.LoadedAt:yyyy-MM-dd HH:mm} UTC, within {freshness}.",
                    $"{name} was loaded {list.LoadedAt:yyyy-MM-dd HH:mm} UTC, more than {freshness} ago.", I, SignatureSubIndication.TryLater);
            }

            Check("eIDAS/TLNotExpired", list.NextUpdate is not { } next || next >= facts.ValidationTime,
                $"{name} has not expired.", $"{name} expired: its NextUpdate was {list.NextUpdate:yyyy-MM-dd HH:mm} UTC.", I, SignatureSubIndication.TryLater);
            Check("eIDAS/TLWellSigned", list.IsWellSigned, $"{name} is signed by its scheme operator.",
                $"{name} is not signed by its scheme operator.", I, SignatureSubIndication.NoCertificateChainFound);
            if (tree.Find("eIDAS/TLVersion") is { } version)
            {
                Check("eIDAS/TLVersion", version.Ids.Count == 0 || (list.Version is not null && version.Ids.Contains(list.Version)),
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
                    _constraints.Add(new(path, ConstraintStatus.NotChecked, null, "Not evaluated by SimpleSign."));
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

    /// <summary>The EU DSS name of a digest algorithm OID.</summary>
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
        };
    }
}
