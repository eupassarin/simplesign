using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>Outcome of checking a signature against the ICP-Brasil policy it declares.</summary>
public enum IcpBrasilPolicyStatus
{
    /// <summary>The signature declares no signature policy.</summary>
    None,

    /// <summary>The declared policy is not an ICP-Brasil policy (outside 2.16.76.1.7.1).</summary>
    NotIcpBrasil,

    /// <summary>An ICP-Brasil policy OID that is not in the embedded LPA (newer, XAdES or unknown).</summary>
    Unknown,

    /// <summary>The policy hash, signing period and required elements are satisfied.</summary>
    Valid,

    /// <summary>At least one requirement of the policy is not met.</summary>
    Invalid,
}

/// <summary>The result of <see cref="IcpBrasilPolicyValidator.Validate(CmsSignedData, DateTimeOffset, IcpBrasilPolicyFormat?, X509Certificate2?)"/>.</summary>
/// <param name="Status">The outcome.</param>
/// <param name="Reference">The policy reference read from the signature.</param>
/// <param name="Policy">The matching LPA entry, when the OID is known.</param>
/// <param name="Errors">Requirements that are not met.</param>
public sealed record IcpBrasilPolicyValidationResult(
    IcpBrasilPolicyStatus Status,
    SignaturePolicyReference? Reference,
    IcpBrasilSignaturePolicy? Policy,
    IReadOnlyList<string> Errors);

/// <summary>
/// Checks a CMS signature against the ICP-Brasil signature policy (PA) it declares in its
/// signature-policy-identifier attribute (DOC-ICP-15.03): the sigPolicyHash matches the PA, the
/// policy could be used at the signing time, and AD-RT and above carry a signature timestamp.
/// </summary>
public static class IcpBrasilPolicyValidator
{
    /// <summary>Validates <paramref name="signature"/> against its declared ICP-Brasil policy.</summary>
    /// <param name="signature">The parsed CMS signature.</param>
    /// <param name="signingTime">The signing time: the signature timestamp time when there is one.</param>
    /// <param name="expectedFormat">The container format (PAdES for PDF signatures, CAdES for .p7s), when known.</param>
    /// <exception cref="ArgumentNullException"><paramref name="signature"/> is null.</exception>
    public static IcpBrasilPolicyValidationResult Validate(
        CmsSignedData signature, DateTimeOffset signingTime, IcpBrasilPolicyFormat? expectedFormat = null) =>
        Validate(signature, signingTime, expectedFormat, signerRoot: null);

    /// <summary>
    /// Validates <paramref name="signature"/> against its declared ICP-Brasil policy, including the
    /// policy's rules: the root of the signer's chain must be one the PA accepts, the mandatory
    /// signed and unsigned attributes must be present and the signature algorithm must be allowed.
    /// </summary>
    /// <param name="signature">The parsed CMS signature.</param>
    /// <param name="signingTime">The signing time: the signature timestamp time when there is one.</param>
    /// <param name="expectedFormat">The container format, when known.</param>
    /// <param name="signerRoot">The root certificate of the signer's chain (see <see cref="IcpBrasilChainValidator.FindBundledRoot(System.Security.Cryptography.X509Certificates.X509Certificate2, IEnumerable{System.Security.Cryptography.X509Certificates.X509Certificate2})"/>); null skips the root check.</param>
    public static IcpBrasilPolicyValidationResult Validate(
        CmsSignedData signature, DateTimeOffset signingTime, IcpBrasilPolicyFormat? expectedFormat, X509Certificate2? signerRoot)
    {
        ArgumentNullException.ThrowIfNull(signature);
        var reference = signature.SignedAttrs is { } attrs ? CmsAttribute.ReadSignaturePolicy(attrs) : null;
        return ValidateReference(reference, signingTime, signature.SignatureTimestampToken is not null, expectedFormat,
            rules => CheckRules(rules, signature, signerRoot));
    }

    /// <summary>
    /// Validates a PDF signature against its declared ICP-Brasil PAdES policy: everything
    /// <see cref="Validate(CmsSignedData, DateTimeOffset, IcpBrasilPolicyFormat?, X509Certificate2?)"/>
    /// checks, plus the PDF structures the PA mandates (DOC-ICP-15.03, attributes 2.16.76.1.8.1–3):
    /// the <c>/Filter /PBAD_PAdES /SubFilter /PBAD.PAdES</c> signature dictionary; for AD-RC and
    /// AD-RA, a DSS with certificates and revocation data, a VRI entry for the signature and a later
    /// document timestamp; for AD-RA, the PA, LPA and LPA signature in the DSS and the VRI.
    /// </summary>
    /// <param name="signature">The parsed CMS signature.</param>
    /// <param name="signingTime">The signing time: the signature timestamp time when there is one.</param>
    /// <param name="signerRoot">The root certificate of the signer's chain; null skips the root check.</param>
    /// <param name="pdf">The PDF structures around the signature.</param>
    public static IcpBrasilPolicyValidationResult Validate(
        CmsSignedData signature, DateTimeOffset signingTime, X509Certificate2? signerRoot, PdfSignatureFacts pdf)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pdf);
        var reference = signature.SignedAttrs is { } attrs ? CmsAttribute.ReadSignaturePolicy(attrs) : null;
        return ValidateReference(reference, signingTime, signature.SignatureTimestampToken is not null, IcpBrasilPolicyFormat.Pades,
            rules => CheckRules(rules, signature, signerRoot),
            info => info.Format == IcpBrasilPolicyFormat.Pades ? CheckPdf(info.Policy, pdf) : []);
    }

    /// <summary>
    /// Validates a signature policy reference read from a signature in another format, such as a
    /// XAdES SignaturePolicyIdentifier (<c>XadesValidationResult.SignaturePolicy</c>): the
    /// SigPolicyHash matches the PA, the policy could be used at the signing time and AD-RT and
    /// above carry a signature timestamp. The attribute and algorithm rules of the PA are not
    /// checked here (SimpleSign.Brasil.Xades checks them for XAdES); the accepted roots are, when
    /// <paramref name="signerRoot"/> is given.
    /// </summary>
    /// <param name="reference">The policy reference; null yields <see cref="IcpBrasilPolicyStatus.None"/>.</param>
    /// <param name="signingTime">The signing time: the signature timestamp time when there is one.</param>
    /// <param name="hasSignatureTimestamp">Whether the signature carries a signature timestamp.</param>
    /// <param name="expectedFormat">The container format (<see cref="IcpBrasilPolicyFormat.Xades"/> for XAdES), when known.</param>
    /// <param name="signerRoot">The root certificate of the signer's chain; null skips the root check.</param>
    public static IcpBrasilPolicyValidationResult Validate(
        SignaturePolicyReference? reference, DateTimeOffset signingTime, bool hasSignatureTimestamp,
        IcpBrasilPolicyFormat? expectedFormat = null, X509Certificate2? signerRoot = null) =>
        ValidateReference(reference, signingTime, hasSignatureTimestamp, expectedFormat,
            rules => CheckRoot(rules, signerRoot));

    private static IcpBrasilPolicyValidationResult ValidateReference(
        SignaturePolicyReference? reference, DateTimeOffset signingTime, bool hasSignatureTimestamp,
        IcpBrasilPolicyFormat? expectedFormat, Func<IcpBrasilPolicyRules, IEnumerable<string>> checkRules,
        Func<IcpBrasilPolicyInfo, IEnumerable<string>>? checkPolicy = null)
    {
        if (reference is null)
        {
            return new(IcpBrasilPolicyStatus.None, null, null, []);
        }

        if (!IcpBrasilPolicyInfo.TryParse(reference.Oid, out var info))
        {
            return new(IcpBrasilPolicyStatus.NotIcpBrasil, reference, null, []);
        }

        if (!IcpBrasilSignaturePolicies.TryFind(reference.Oid, out var policy))
        {
            return new(IcpBrasilPolicyStatus.Unknown, reference, null,
                [$"Signature policy {reference.Oid} is not in the embedded ICP-Brasil LPA."]);
        }

        var errors = new List<string>();
        if (reference.Hash.IsEmpty)
        {
            errors.Add("sigPolicyHash is empty; ICP-Brasil policies require the hash of the PA.");
        }
        else if (reference.HashAlgorithmOid != policy.HashAlgorithmOid || !reference.Hash.Span.SequenceEqual(policy.PolicyHash.Span))
        {
            errors.Add($"sigPolicyHash does not match the hash of {policy.Uri}.");
        }

        if (signingTime < policy.NotBefore || signingTime > policy.NotAfter)
        {
            errors.Add($"Policy {policy.Oid} could only be used from {policy.NotBefore:yyyy-MM-dd} to {policy.NotAfter:yyyy-MM-dd}; the signature is from {signingTime:yyyy-MM-dd}.");
        }
        else if (policy.RevokedAt is { } revoked && signingTime >= revoked)
        {
            errors.Add($"Policy {policy.Oid} was revoked on {revoked:yyyy-MM-dd}, before the signature ({signingTime:yyyy-MM-dd}).");
        }

        if (policy.RequiresSignatureTimestamp && !hasSignatureTimestamp)
        {
            errors.Add($"Policy {info.Policy} requires a signature timestamp, and the signature has none.");
        }

        if (expectedFormat is { } format && format != info.Format)
        {
            errors.Add($"Policy {policy.Oid} is a {info.Format} policy, but the signature is {format}.");
        }

        if (IcpBrasilSignaturePolicies.TryGetRules(policy.Oid, out var rules))
        {
            errors.AddRange(checkRules(rules));
        }

        if (checkPolicy is not null)
        {
            errors.AddRange(checkPolicy(info));
        }

        return new(errors.Count == 0 ? IcpBrasilPolicyStatus.Valid : IcpBrasilPolicyStatus.Invalid, reference, policy, errors.AsReadOnly());
    }

    // PAdES PAs mandate ICP-Brasil attributes in the 2.16.76.1.8 arc that describe PDF structures
    // (DSS/VRI/document timestamps), not CMS attributes; they are checked on the PDF (CheckPdf).
    private const string PdfStructureArc = "2.16.76.1.8.";

    // DOC-ICP-15.03 Table A.22 and the PAs' br_ext_mandatedPdfSigDicEntries, br_ext_dss and
    // br_ext_mandatedDocTSEntries: the same in every version of a policy.
    private static List<string> CheckPdf(IcpBrasilPolicy policy, PdfSignatureFacts pdf)
    {
        var errors = new List<string>();
        if (pdf.Filter != "PBAD_PAdES" || pdf.SubFilter != "PBAD.PAdES")
        {
            errors.Add($"ICP-Brasil PAdES policies require /Filter /PBAD_PAdES and /SubFilter /PBAD.PAdES (2.16.76.1.8.1); the signature has /Filter /{pdf.Filter} /SubFilter /{pdf.SubFilter}.");
        }

        if (policy is not (IcpBrasilPolicy.AdRc or IcpBrasilPolicy.AdRa))
        {
            return errors;
        }

        if (!pdf.HasDss)
        {
            errors.Add($"{policy} requires a DSS dictionary (2.16.76.1.8.2), and the document has none.");
        }
        else
        {
            if (!pdf.DssKeys.Contains("Certs"))
            {
                errors.Add("The DSS has no Certs (2.16.76.1.8.2).");
            }

            if (!pdf.DssKeys.Contains("OCSPs") && !pdf.DssKeys.Contains("CRLs"))
            {
                errors.Add("The DSS has neither OCSPs nor CRLs; the policy requires either (2.16.76.1.8.2).");
            }

            if (!pdf.HasVri)
            {
                errors.Add("The DSS has no VRI entry for this signature (2.16.76.1.8.2).");
            }
            else if (!pdf.VriKeys.Contains("OCSP") && !pdf.VriKeys.Contains("CRL"))
            {
                errors.Add("The signature's VRI entry has neither OCSP nor CRL; the policy requires either (2.16.76.1.8.2).");
            }
        }

        if (!pdf.HasLaterDocumentTimestamp)
        {
            errors.Add($"{policy} requires a document timestamp (ETSI.RFC3161) after the signature (2.16.76.1.8.3).");
        }

        if (policy == IcpBrasilPolicy.AdRa && pdf.HasDss)
        {
            foreach (var key in new[] { IcpBrasilPolicyArtifacts.DssPolicyArtifacts, IcpBrasilPolicyArtifacts.DssLpaArtifacts, IcpBrasilPolicyArtifacts.DssLpaSignatures }
                .Where(k => !pdf.DssKeys.Contains(k)))
            {
                errors.Add($"AD-RA requires {key} in the DSS (2.16.76.1.8.2).");
            }

            foreach (var key in new[] { IcpBrasilPolicyArtifacts.VriPolicyArtifact, IcpBrasilPolicyArtifacts.VriLpaArtifact, IcpBrasilPolicyArtifacts.VriLpaSignature }
                .Where(k => pdf.HasVri && !pdf.VriKeys.Contains(k)))
            {
                errors.Add($"AD-RA requires {key} in the signature's VRI entry (2.16.76.1.8.2).");
            }
        }

        return errors;
    }

    private static List<string> CheckRoot(IcpBrasilPolicyRules rules, X509Certificate2? signerRoot)
    {
        var errors = new List<string>();
        if (signerRoot is not null && rules.TrustAnchorKeySha256.Count > 0 && !rules.AcceptsRoot(signerRoot))
        {
            errors.Add($"Policy {rules.Oid} does not accept the signer's root ({signerRoot.GetNameInfo(X509NameType.SimpleName, false)}); "
                + $"it accepts: {string.Join(", ", rules.TrustAnchorSubjects.Select(SimpleName))}.");
        }

        return errors;
    }

    private static List<string> CheckRules(IcpBrasilPolicyRules rules, CmsSignedData signature, X509Certificate2? signerRoot)
    {
        var errors = CheckRoot(rules, signerRoot);
        var signedOids = SignedAttributeOids(signature.SignedAttrs);
        foreach (string oid in rules.MandatedSignedAttributes.Where(o => !signedOids.Contains(o)))
        {
            errors.Add($"Policy {rules.Oid} requires the signed attribute {oid}, which is missing.");
        }

        var unsigned = signature.UnsignedAttributes ?? new Dictionary<string, byte[][]>();
        foreach (string oid in rules.MandatedUnsignedAttributes.Where(o => !o.StartsWith(PdfStructureArc, StringComparison.Ordinal) && !unsigned.ContainsKey(o)))
        {
            errors.Add($"Policy {rules.Oid} requires the unsigned attribute {oid}, which is missing.");
        }

        if (rules.SignerAlgorithms.Count > 0)
        {
            var allowed = rules.SignerAlgorithms.FirstOrDefault(a => a.Oid == signature.SignatureAlgorithmOid);
            if (allowed is null)
            {
                errors.Add($"Policy {rules.Oid} does not allow the signature algorithm {signature.SignatureAlgorithmOid}.");
            }
            else if (allowed.MinKeyLength is { } min && KeySize(signature.SignerCertificate) is { } size && size < min)
            {
                errors.Add($"Policy {rules.Oid} requires keys of at least {min} bits; the signer key has {size}.");
            }
        }

        return errors;
    }

    private static string SimpleName(string subject)
    {
        int cn = subject.IndexOf("CN=", StringComparison.Ordinal);
        if (cn < 0)
        {
            return subject;
        }

        int end = subject.IndexOf(',', cn);
        return end < 0 ? subject[(cn + 3)..] : subject[(cn + 3)..end];
    }

    private static HashSet<string> SignedAttributeOids(byte[]? signedAttrs)
    {
        var oids = new HashSet<string>(StringComparer.Ordinal);
        if (signedAttrs is null)
        {
            return oids;
        }

        try
        {
            var set = new System.Formats.Asn1.AsnReader(signedAttrs, System.Formats.Asn1.AsnEncodingRules.BER).ReadSetOf(skipSortOrderValidation: true);
            while (set.HasData)
            {
                oids.Add(set.ReadSequence().ReadObjectIdentifier());
            }
        }
        catch (System.Formats.Asn1.AsnContentException)
        {
            // Malformed attributes: report them all as missing.
        }

        return oids;
    }

    private static int? KeySize(X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return null;
        }

        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.KeySize;
        }

        using var ec = certificate.GetECDsaPublicKey();
        return ec?.KeySize;
    }
}
