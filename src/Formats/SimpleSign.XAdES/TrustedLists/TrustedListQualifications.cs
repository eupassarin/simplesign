using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SimpleSign.XAdES.TrustedLists;

/// <summary>
/// The service information extensions of a trust service, current or from its history (ETSI TS 119 612 §5.5.9):
/// additional service information, the qualifications of the certificates it issued, and the expiry of revocation
/// information.
/// </summary>
public sealed record TrustedListServiceExtensions
{
    /// <summary>No extension.</summary>
    public static TrustedListServiceExtensions None { get; } = new();

    /// <summary>The AdditionalServiceInformation URIs, e.g. <c>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</c>.</summary>
    public IReadOnlyList<string> AdditionalServiceInformation { get; init; } = [];

    /// <summary>The Qualifications extension: each qualifier, with the certificates it applies to.</summary>
    public IReadOnlyList<TrustedListQualification> Qualifications { get; init; } = [];

    /// <summary>The ExpiredCertsRevocationInfo extension: from when revocation information covers expired certificates; null when absent.</summary>
    public DateTimeOffset? ExpiredCertsRevocationInfo { get; init; }

    /// <summary>Whether <see cref="AdditionalServiceInformation"/> has a URI ending with <paramref name="ending"/> (<c>/ForeSignatures</c>).</summary>
    /// <param name="ending">The ending of the URI.</param>
    /// <returns>Whether it is there.</returns>
    public bool HasAdditionalInformation(string ending) =>
        AdditionalServiceInformation.Any(u => u.EndsWith(ending, StringComparison.OrdinalIgnoreCase));

    /// <summary>The qualifier URIs that apply to <paramref name="certificate"/>: those whose criteria it meets.</summary>
    /// <param name="certificate">A certificate issued by the service.</param>
    /// <returns>The qualifier URIs.</returns>
    public IReadOnlyList<string> QualifiersFor(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return [.. Qualifications.Where(q => q.Criteria.Matches(certificate)).SelectMany(q => q.Qualifiers).Distinct(StringComparer.Ordinal)];
    }
}

/// <summary>One QualificationElement: qualifier URIs and the certificates they apply to.</summary>
/// <param name="Qualifiers">The qualifier URIs, e.g. <c>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD</c>.</param>
/// <param name="Criteria">Which certificates they apply to.</param>
public sealed record TrustedListQualification(IReadOnlyList<string> Qualifiers, TrustedListCriteria Criteria);

/// <summary>
/// A CriteriaList (ETSI TS 119 612 §5.5.9.2): key usage bits, policy sets, extended key usages, subject attributes
/// and nested lists, combined by <see cref="Assert"/>.
/// </summary>
public sealed record TrustedListCriteria
{
    /// <summary><c>all</c>, <c>atLeastOne</c> or <c>none</c>.</summary>
    public string Assert { get; init; } = "all";

    /// <summary>Each KeyUsage criterion: the bits (by name, such as <c>nonRepudiation</c>) and the value each must have.</summary>
    public IReadOnlyList<IReadOnlyDictionary<string, bool>> KeyUsages { get; init; } = [];

    /// <summary>Each PolicySet criterion: the certificate policy OIDs that must all be present.</summary>
    public IReadOnlyList<IReadOnlyList<string>> PolicySets { get; init; } = [];

    /// <summary>Each ExtendedKeyUsage criterion: the key purpose OIDs that must all be present.</summary>
    public IReadOnlyList<IReadOnlyList<string>> ExtendedKeyUsages { get; init; } = [];

    /// <summary>Each CertSubjectDNAttribute criterion: the subject attribute OIDs that must all be present.</summary>
    public IReadOnlyList<IReadOnlyList<string>> SubjectAttributes { get; init; } = [];

    /// <summary>Nested criteria lists.</summary>
    public IReadOnlyList<TrustedListCriteria> Nested { get; init; } = [];

    /// <summary>Whether <paramref name="certificate"/> meets the criteria.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>Whether it matches.</returns>
    public bool Matches(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault()?.KeyUsages;
        var policies = CertificatePolicies(certificate);
        var purposes = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(e => e.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>()).Select(o => o.Value).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var attributes = certificate.SubjectName.EnumerateRelativeDistinguishedNames()
            .Select(r => r.GetSingleElementType().Value).OfType<string>().ToHashSet(StringComparer.Ordinal);

        var results = new List<bool>();
        results.AddRange(KeyUsages.Select(bits => bits.All(b => HasBit(keyUsage, b.Key) == b.Value)));
        results.AddRange(PolicySets.Select(set => set.All(policies.Contains)));
        results.AddRange(ExtendedKeyUsages.Select(set => set.All(purposes.Contains)));
        results.AddRange(SubjectAttributes.Select(set => set.All(attributes.Contains)));
        results.AddRange(Nested.Select(n => n.Matches(certificate)));
        return Assert switch
        {
            "atLeastOne" => results.Any(r => r),
            "none" => !results.Any(r => r),
            _ => results.All(r => r),
        };
    }

    private static bool HasBit(X509KeyUsageFlags? flags, string name)
    {
        var bit = name switch
        {
            "digitalSignature" => X509KeyUsageFlags.DigitalSignature,
            "nonRepudiation" or "contentCommitment" => X509KeyUsageFlags.NonRepudiation,
            "keyEncipherment" => X509KeyUsageFlags.KeyEncipherment,
            "dataEncipherment" => X509KeyUsageFlags.DataEncipherment,
            "keyAgreement" => X509KeyUsageFlags.KeyAgreement,
            "keyCertSign" => X509KeyUsageFlags.KeyCertSign,
            "crlSign" => X509KeyUsageFlags.CrlSign,
            "encipherOnly" => X509KeyUsageFlags.EncipherOnly,
            "decipherOnly" => X509KeyUsageFlags.DecipherOnly,
            _ => X509KeyUsageFlags.None,
        };
        return bit != X509KeyUsageFlags.None && flags is { } f && (f & bit) == bit;
    }

    /// <summary>The policy OIDs of the certificatePolicies extension (RFC 5280 §4.2.1.4).</summary>
    internal static HashSet<string> CertificatePolicies(X509Certificate2 certificate)
    {
        var oids = new HashSet<string>(StringComparer.Ordinal);
        if (certificate.Extensions["2.5.29.32"] is not { } extension)
        {
            return oids;
        }

        try
        {
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (reader.HasData)
            {
                var info = reader.ReadSequence();
                oids.Add(info.ReadObjectIdentifier());
            }
        }
        catch (AsnContentException)
        {
            // A malformed extension names no policy.
        }

        return oids;
    }
}

/// <summary>Reads the ServiceInformationExtensions of a ServiceInformation or ServiceHistoryInstance.</summary>
internal static class TrustedListExtensionReader
{
    public static TrustedListServiceExtensions Read(XmlNode serviceInformation)
    {
        var extensions = Children(serviceInformation, "ServiceInformationExtensions").SelectMany(e => Children(e, "Extension")).ToList();
        if (extensions.Count == 0)
        {
            return TrustedListServiceExtensions.None;
        }

        var additional = new List<string>();
        var qualifications = new List<TrustedListQualification>();
        DateTimeOffset? expiredCertsRevocationInfo = null;
        foreach (var extension in extensions)
        {
            foreach (var content in Elements(extension))
            {
                switch (content.LocalName)
                {
                    case "AdditionalServiceInformation":
                        additional.AddRange(Children(content, "URI").Select(u => u.InnerText.Trim()).Where(u => u.Length > 0));
                        break;
                    case "Qualifications":
                        foreach (var element in Children(content, "QualificationElement"))
                        {
                            var qualifiers = Children(element, "Qualifiers").SelectMany(q => Children(q, "Qualifier"))
                                .Select(q => q.GetAttribute("uri").Trim()).Where(u => u.Length > 0).ToList();
                            var criteria = Children(element, "CriteriaList").Select(Criteria).FirstOrDefault() ?? new TrustedListCriteria();
                            qualifications.Add(new TrustedListQualification(qualifiers, criteria));
                        }

                        break;
                    case "ExpiredCertsRevocationInfo":
                        if (DateTimeOffset.TryParse(content.InnerText.Trim(), System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.AssumeUniversal, out var since))
                        {
                            expiredCertsRevocationInfo = since;
                        }

                        break;
                    default:
                        break;
                }
            }
        }

        return new TrustedListServiceExtensions
        {
            AdditionalServiceInformation = additional,
            Qualifications = qualifications,
            ExpiredCertsRevocationInfo = expiredCertsRevocationInfo,
        };
    }

    private static TrustedListCriteria Criteria(XmlElement list)
    {
        var keyUsages = new List<IReadOnlyDictionary<string, bool>>();
        var policySets = new List<IReadOnlyList<string>>();
        var purposes = new List<IReadOnlyList<string>>();
        var attributes = new List<IReadOnlyList<string>>();
        var nested = new List<TrustedListCriteria>();
        foreach (var criterion in Elements(list))
        {
            switch (criterion.LocalName)
            {
                case "KeyUsage":
                    keyUsages.Add(Children(criterion, "KeyUsageBit").ToDictionary(
                        b => b.GetAttribute("name"), b => string.Equals(b.InnerText.Trim(), "true", StringComparison.OrdinalIgnoreCase), StringComparer.Ordinal));
                    break;
                case "PolicySet":
                    policySets.Add(Identifiers(Children(criterion, "PolicyIdentifier")));
                    break;
                case "CriteriaList":
                    nested.Add(Criteria(criterion));
                    break;
                case "otherCriteriaList":
                    foreach (var other in Elements(criterion))
                    {
                        if (other.LocalName == "ExtendedKeyUsage")
                        {
                            purposes.Add(Identifiers(Children(other, "KeyPurposeId")));
                        }
                        else if (other.LocalName == "CertSubjectDNAttribute")
                        {
                            attributes.Add(Identifiers(Children(other, "AttributeOID")));
                        }
                    }

                    break;
                default:
                    break;
            }
        }

        string assert = list.GetAttribute("assert");
        return new TrustedListCriteria
        {
            Assert = assert.Length > 0 ? assert : "all",
            KeyUsages = keyUsages,
            PolicySets = policySets,
            ExtendedKeyUsages = purposes,
            SubjectAttributes = attributes,
            Nested = nested,
        };
    }

    /// <summary>The OIDs of xades:Identifier children (an <c>urn:oid:</c> prefix removed).</summary>
    private static List<string> Identifiers(IEnumerable<XmlElement> holders) =>
        [.. holders.SelectMany(h => Children(h, "Identifier")).Select(i => i.InnerText.Trim())
            .Select(v => v.StartsWith("urn:oid:", StringComparison.OrdinalIgnoreCase) ? v["urn:oid:".Length..] : v).Where(v => v.Length > 0)];

    private static IEnumerable<XmlElement> Elements(XmlNode node) => node.ChildNodes.OfType<XmlElement>();

    private static IEnumerable<XmlElement> Children(XmlNode node, string localName) => Elements(node).Where(e => e.LocalName == localName);
}
