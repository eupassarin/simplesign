using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Validation.Policy;

/// <summary>What a format validator found, in the terms the evaluator needs.</summary>
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

    /// <summary>A trusted time the signature is proven to exist at (signature timestamp), or null.</summary>
    public DateTimeOffset? ProofOfExistence { get; init; }
    public DateTimeOffset ValidationTime { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>The indication, sub-indication and checks of a validation.</summary>
internal sealed record ValidationEvaluation(
    SignatureIndication Indication,
    SignatureSubIndication? SubIndication,
    IReadOnlyList<ValidationConstraintResult> Constraints,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Turns the facts of a validation into an ETSI EN 319 102-1 style outcome: an indication, the sub-indication
/// of the first decisive failure, and the list of checks, including the constraints of a <see cref="ValidationPolicy"/>.
/// </summary>
internal static class ValidationPolicyEvaluator
{
    internal static ValidationEvaluation Evaluate(ValidationFacts facts, ValidationPolicy policy)
    {
        var constraints = new List<ValidationConstraintResult>();
        var warnings = new List<string>();
        (SignatureIndication Indication, SignatureSubIndication? Sub)? decided = null;

        void Decide(SignatureIndication indication, SignatureSubIndication? sub) => decided ??= (indication, sub);

        // Integrity of the signed data.
        if (facts.IsIntegrityValid)
        {
            constraints.Add(new("integrity", ConstraintStatus.Passed, null, "The signed data matches the signature."));
        }
        else
        {
            constraints.Add(new("integrity", ConstraintStatus.Failed, SignatureSubIndication.HashFailure, "The signed data does not match the signature."));
            Decide(SignatureIndication.Invalid, SignatureSubIndication.HashFailure);
        }

        // Signing certificate and signature value.
        if (facts.SignerCertificate is null)
        {
            constraints.Add(new("signingCertificate", ConstraintStatus.Failed, SignatureSubIndication.NoSigningCertificateFound, "The signing certificate was not found."));
            Decide(SignatureIndication.Indeterminate, SignatureSubIndication.NoSigningCertificateFound);
        }

        if (facts.IsSignatureVerificationIndeterminate)
        {
            constraints.Add(new("signatureValue", ConstraintStatus.Indeterminate, SignatureSubIndication.CryptoConstraintsFailure, "The signature algorithm is not supported."));
            Decide(SignatureIndication.Indeterminate, SignatureSubIndication.CryptoConstraintsFailure);
        }
        else if (facts.IsSignatureValid)
        {
            constraints.Add(new("signatureValue", ConstraintStatus.Passed, null, "The signature value verifies with the signing certificate."));
        }
        else
        {
            constraints.Add(new("signatureValue", ConstraintStatus.Failed, SignatureSubIndication.SigCryptoFailure, "The signature value does not verify with the signing certificate."));
            Decide(SignatureIndication.Invalid, SignatureSubIndication.SigCryptoFailure);
        }

        // Revocation.
        switch (facts.IsNotRevoked)
        {
            case null:
                constraints.Add(new("revocation", ConstraintStatus.NotChecked, null, "Revocation was not checked."));
                break;
            case true:
                constraints.Add(new("revocation", ConstraintStatus.Passed, null, $"The signing certificate is not revoked ({facts.RevocationSource})."));
                break;
            default:
                if (facts.RevocationSource is RevocationSource.None or RevocationSource.Indeterminate)
                {
                    constraints.Add(new("revocation", ConstraintStatus.Indeterminate, SignatureSubIndication.TryLater, "The revocation status could not be established."));
                    Decide(SignatureIndication.Indeterminate, SignatureSubIndication.TryLater);
                }
                else
                {
                    constraints.Add(new("revocation", ConstraintStatus.Failed, SignatureSubIndication.Revoked, $"The signing certificate is revoked ({facts.RevocationSource})."));
                    Decide(SignatureIndication.Invalid, SignatureSubIndication.Revoked);
                }

                break;
        }

        // Policy: cryptographic constraints and signing certificate constraints.
        EvaluateDigest(facts, policy.Cryptographic, constraints, warnings, Decide);
        EvaluateKey(facts, policy.Cryptographic, constraints, warnings, Decide);
        EvaluateKeyUsage(facts, policy.SigningCertificate.KeyUsage, constraints, warnings, Decide);

        // Document timestamps whose chain is only a warning need a trusted TSA.
        if (facts.IsDocumentTimestamp && facts.IsChainTrustWarning && facts.IsTsaTrusted != true)
        {
            Decide(SignatureIndication.Indeterminate, SignatureSubIndication.NoCertificateChainFound);
        }

        // Certificate chain.
        if (facts.IsCertificateChainValid || facts.IsChainTrustWarning)
        {
            constraints.Add(new("certificateChain", facts.IsCertificateChainValid ? ConstraintStatus.Passed : ConstraintStatus.Warning, null,
                facts.IsCertificateChainValid ? "The certificate chain reaches a trust anchor." : "The chain is trusted by a country provider only."));
        }
        else
        {
            var sub = ChainSubIndication(facts);
            constraints.Add(new("certificateChain", ConstraintStatus.Failed, sub, "The certificate chain could not be validated to a trust anchor."));
            Decide(sub == SignatureSubIndication.NotYetValid ? SignatureIndication.Invalid : SignatureIndication.Indeterminate, sub);
        }

        var outcome = decided ?? (SignatureIndication.Valid, null);
        return new ValidationEvaluation(outcome.Indication, outcome.Sub, constraints, warnings);
    }

    private static SignatureSubIndication ChainSubIndication(ValidationFacts facts)
    {
        var certificate = facts.SignerCertificate;
        if (certificate is null)
        {
            return SignatureSubIndication.NoCertificateChainFound;
        }

        var time = facts.ProofOfExistence ?? facts.ValidationTime;
        if (certificate.NotBefore.ToUniversalTime() > time)
        {
            return SignatureSubIndication.NotYetValid;
        }

        return certificate.NotAfter.ToUniversalTime() < time
            ? SignatureSubIndication.OutOfBoundsNoPoe
            : SignatureSubIndication.NoCertificateChainFound;
    }

    private static void EvaluateDigest(
        ValidationFacts facts, CryptographicConstraints crypto, List<ValidationConstraintResult> constraints,
        List<string> warnings, Action<SignatureIndication, SignatureSubIndication?> decide)
    {
        if (crypto.Level == ConstraintLevel.Ignore || facts.DigestAlgorithmOid is null)
        {
            return;
        }

        string name = DigestName(facts.DigestAlgorithmOid);
        var accepted = crypto.DigestAlgorithms.FirstOrDefault(a => string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase));
        string? failure = accepted is null
            ? $"The digest algorithm {name} is not accepted by the validation policy."
            : accepted.AcceptedUntil is { } until && (facts.ProofOfExistence ?? facts.ValidationTime) > until
                ? $"The digest algorithm {name} is accepted only until {until:yyyy-MM-dd}, and nothing proves the signature existed before."
                : null;
        Record(constraints, warnings, decide, "crypto.digestAlgorithm", crypto.Level, failure,
            $"The digest algorithm {name} is accepted.", SignatureSubIndication.CryptoConstraintsFailureNoPoe);
    }

    private static void EvaluateKey(
        ValidationFacts facts, CryptographicConstraints crypto, List<ValidationConstraintResult> constraints,
        List<string> warnings, Action<SignatureIndication, SignatureSubIndication?> decide)
    {
        var certificate = facts.SignerCertificate;
        if (crypto.Level == ConstraintLevel.Ignore || certificate is null)
        {
            return;
        }

        string? keyAlgorithm = certificate.PublicKey.Oid.Value;
        string? failure = null;
        string passed;
        if (keyAlgorithm is Oids.RsaEncryption or Oids.RsaPss)
        {
            int size = RsaKeySize(certificate);
            passed = $"The RSA key has {size} bits.";
            if (crypto.MinimumRsaKeySize > 0 && size < crypto.MinimumRsaKeySize)
            {
                failure = $"The RSA key has {size} bits; the policy requires at least {crypto.MinimumRsaKeySize}.";
            }
        }
        else if (keyAlgorithm == Oids.EcPublicKey)
        {
            string? curve = NamedCurve(certificate);
            passed = $"The elliptic curve {curve} is accepted.";
            if (crypto.EllipticCurves.Count > 0 && (curve is null || !crypto.EllipticCurves.Contains(curve)))
            {
                failure = $"The elliptic curve {curve ?? "(explicit parameters)"} is not accepted by the policy.";
            }
        }
        else
        {
            return;
        }

        Record(constraints, warnings, decide, "crypto.publicKey", crypto.Level, failure, passed, SignatureSubIndication.CryptoConstraintsFailureNoPoe);
    }

    private static void EvaluateKeyUsage(
        ValidationFacts facts, ConstraintLevel level, List<ValidationConstraintResult> constraints,
        List<string> warnings, Action<SignatureIndication, SignatureSubIndication?> decide)
    {
        var certificate = facts.SignerCertificate;
        if (level == ConstraintLevel.Ignore || certificate is null || facts.IsDocumentTimestamp)
        {
            return;
        }

        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        bool allows = keyUsage is not null
            && (keyUsage.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) != 0;
        Record(constraints, warnings, decide, "signingCertificate.keyUsage", level,
            allows ? null : "The signing certificate has neither digitalSignature nor nonRepudiation in its key usage.",
            "The signing certificate allows digital signatures.", SignatureSubIndication.SigConstraintsFailure);
    }

    private static void Record(
        List<ValidationConstraintResult> constraints, List<string> warnings,
        Action<SignatureIndication, SignatureSubIndication?> decide,
        string id, ConstraintLevel level, string? failure, string passed, SignatureSubIndication sub)
    {
        if (failure is null)
        {
            constraints.Add(new(id, ConstraintStatus.Passed, null, passed));
        }
        else if (level == ConstraintLevel.Warn)
        {
            constraints.Add(new(id, ConstraintStatus.Warning, sub, failure));
            warnings.Add(failure);
        }
        else
        {
            constraints.Add(new(id, ConstraintStatus.Failed, sub, failure));
            decide(SignatureIndication.Indeterminate, sub);
        }
    }

    internal static string DigestName(string oid) => oid switch
    {
        "1.2.840.113549.2.5" => "MD5",
        "1.3.14.3.2.26" => "SHA1",
        "2.16.840.1.101.3.4.2.4" => "SHA224",
        "2.16.840.1.101.3.4.2.1" => "SHA256",
        "2.16.840.1.101.3.4.2.2" => "SHA384",
        "2.16.840.1.101.3.4.2.3" => "SHA512",
        "2.16.840.1.101.3.4.2.8" => "SHA3-256",
        "2.16.840.1.101.3.4.2.9" => "SHA3-384",
        "2.16.840.1.101.3.4.2.10" => "SHA3-512",
        _ => oid,
    };

    private static int RsaKeySize(X509Certificate2 certificate)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(certificate.PublicKey.EncodedKeyValue.RawData, out _);
            return rsa.KeySize;
        }
        catch (CryptographicException)
        {
            return 0;
        }
    }

    private static string? NamedCurve(X509Certificate2 certificate)
    {
        try
        {
            if (certificate.PublicKey.EncodedParameters?.RawData is not { Length: > 0 } parameters)
            {
                return null;
            }

            var reader = new AsnReader(parameters, AsnEncodingRules.DER);
            return reader.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier) ? reader.ReadObjectIdentifier() : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
