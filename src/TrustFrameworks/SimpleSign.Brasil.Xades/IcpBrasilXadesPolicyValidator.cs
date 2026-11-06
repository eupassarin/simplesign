using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.XAdES;

namespace SimpleSign.Brasil.Xades;

/// <summary>Checks a XAdES signature against the ICP-Brasil XML policy it declares.</summary>
public static class IcpBrasilXadesPolicyValidator
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary>
    /// Validates the policy of a XAdES signature: the SigPolicyHash matches the PA's
    /// SignPolicyDigest, the policy could be used at the signing time, the signer's AC Raiz is one
    /// the PA accepts, every qualifying property the PA mandates is present (e.g. SigningCertificate,
    /// SigAndRefsTimeStamp) and the signature algorithm and key size are allowed.
    /// </summary>
    /// <param name="signedXml">The signed XML.</param>
    /// <param name="result">Its validation result, from <see cref="XadesSignatureValidator"/>.</param>
    public static IcpBrasilPolicyValidationResult Validate(byte[] signedXml, XadesValidationResult result)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        ArgumentNullException.ThrowIfNull(result);
        var root = result.SignerCertificate is { } signer
            ? IcpBrasilChainValidator.FindBundledRoot(signer)
            : null;
        var check = IcpBrasilPolicyValidator.Validate(
            result.SignaturePolicy, result.SigningTime ?? DateTimeOffset.UtcNow,
            hasSignatureTimestamp: result.HasValidSignatureTimeStamp is not null,
            IcpBrasilPolicyFormat.Xades, root);
        if (check.Policy is null || !IcpBrasilSignaturePolicies.TryGetRules(check.Policy.Oid, out var rules))
        {
            return check;
        }

        var errors = new List<string>(check.Errors);
        CheckProperties(signedXml, result.SignatureId, rules, result.SignerCertificate, errors);
        return check with
        {
            Status = errors.Count == 0 ? IcpBrasilPolicyStatus.Valid : IcpBrasilPolicyStatus.Invalid,
            Errors = errors.AsReadOnly(),
        };
    }

    private static void CheckProperties(
        byte[] signedXml, string? signatureId, IcpBrasilPolicyRules rules, X509Certificate2? signer, List<string> errors)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using (var stream = new MemoryStream(signedXml))
        using (var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
        {
            doc.Load(reader);
        }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", DsNamespace);
        ns.AddNamespace("xades", XadesNamespace);
        var signatures = doc.SelectNodes("//ds:Signature", ns)?.OfType<XmlElement>().ToList() ?? [];
        var signature = signatures.FirstOrDefault(s => signatureId is not null && s.GetAttribute("Id") == signatureId) ?? signatures.LastOrDefault();
        if (signature is null)
        {
            errors.Add("The document has no XML signature.");
            return;
        }

        var signedProperties = Names(signature, ns, "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/*");
        var unsignedProperties = Names(signature, ns, "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/*");
        foreach (string property in rules.MandatedSignedAttributes.Where(p => !signedProperties.Contains(p)))
        {
            errors.Add(property == "SigningCertificate" && signedProperties.Contains("SigningCertificateV2")
                ? $"Policy {rules.Oid} requires SigningCertificate (XAdES 1.3.2); the signature has SigningCertificateV2."
                : $"Policy {rules.Oid} requires the signed property {property}, which is missing.");
        }

        foreach (string property in rules.MandatedUnsignedAttributes.Where(p => !unsignedProperties.Contains(p)))
        {
            errors.Add($"Policy {rules.Oid} requires the unsigned property {property}, which is missing.");
        }

        if (rules.SignerAlgorithms.Count == 0)
        {
            return;
        }

        string? method = (signature.SelectSingleNode("ds:SignedInfo/ds:SignatureMethod", ns) as XmlElement)?.GetAttribute("Algorithm");
        var allowed = rules.SignerAlgorithms.FirstOrDefault(a => a.Oid == method);
        if (allowed is null)
        {
            errors.Add($"Policy {rules.Oid} does not allow the signature algorithm {method}.");
        }
        else if (allowed.MinKeyLength is { } min && KeySize(signer) is { } size && size < min)
        {
            errors.Add($"Policy {rules.Oid} requires keys of at least {min} bits; the signer key has {size}.");
        }
    }

    private static HashSet<string> Names(XmlElement signature, XmlNamespaceManager ns, string xpath) =>
        new(signature.SelectNodes(xpath, ns)?.OfType<XmlElement>().Select(e => e.LocalName) ?? [], StringComparer.Ordinal);

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
