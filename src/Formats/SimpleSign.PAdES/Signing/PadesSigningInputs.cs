using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// What the one-call builder and the deferred builder turn their options into the same way: the signature
/// field of a <see cref="SignatureMetadata"/>, the extra signed attributes, the document information keys.
/// </summary>
internal static class PadesSigningInputs
{
    /// <summary>
    /// The field with the signer, reason, location and contact of <paramref name="metadata"/>; values the
    /// metadata leaves out clear the ones the field had.
    /// </summary>
    internal static SignatureFieldOptions ApplyMetadata(SignatureFieldOptions field, SignatureMetadata metadata)
    {
        string? location = metadata.Location ?? metadata.InstitutionName;

        string? contactInfo;
        if (metadata.ContactInfo is not null)
        {
            contactInfo = metadata.ContactInfo;
        }
        else
        {
            var contactParts = new List<string>();
            if (metadata.SignerId is not null)
            {
                string label = metadata.SignerIdType ?? "ID";
                contactParts.Add($"{label}: {metadata.SignerId}");
            }
            if (metadata.Email is not null)
            {
                contactParts.Add($"Email: {metadata.Email}");
            }
            if (metadata.IpAddress is not null)
            {
                contactParts.Add($"IP: {metadata.IpAddress}");
            }
            if (metadata.AuthenticationMethod is not null)
            {
                contactParts.Add($"Auth: {metadata.AuthenticationMethod}");
            }
            if (metadata.InstitutionName is not null)
            {
                contactParts.Add($"Org: {metadata.InstitutionName}");
            }
            contactInfo = contactParts.Count == 0 ? null : string.Join(" | ", contactParts);
        }

        return new SignatureFieldOptions
        {
            FieldName = field.FieldName,
            SignerName = metadata.SignerName,
            Reason = metadata.Reason,
            Location = location,
            ContactInfo = contactInfo,
            ContentsReservedBytes = field.ContentsReservedBytes,
            SubFilter = field.SubFilter,
            Appearance = field.Appearance,
            CertificationLevel = field.CertificationLevel,
            ExistingFieldName = field.ExistingFieldName
        };
    }

    /// <summary>A copy of <paramref name="source"/> the caller cannot change afterwards.</summary>
    internal static SignatureMetadata CopyMetadata(SignatureMetadata source) => new()
    {
        SignerName = source.SignerName,
        SignerId = source.SignerId,
        SignerIdType = source.SignerIdType,
        Email = source.Email,
        IpAddress = source.IpAddress,
        AuthenticationMethod = source.AuthenticationMethod,
        InstitutionName = source.InstitutionName,
        InstitutionId = source.InstitutionId,
        InstitutionIdType = source.InstitutionIdType,
        CommitmentType = source.CommitmentType,
        LegalBasis = source.LegalBasis,
        PolicyOid = source.PolicyOid,
        PolicyUri = source.PolicyUri,
        Reason = source.Reason,
        ContactInfo = source.ContactInfo,
        Location = source.Location,
        ExtraAttributes = source.ExtraAttributes?.ToArray()
    };

    /// <summary>
    /// The signed attributes added to the mandatory ones: the commitment type, the signature policy and the
    /// extra attributes of the metadata, then the signature policy given with its hash. Null when there are none.
    /// </summary>
    internal static IReadOnlyList<CmsAttribute>? ExtraSignedAttributes(SignatureMetadata? metadata, SignaturePolicyReference? signaturePolicy)
    {
        var extraAttributes = new List<CmsAttribute>();
        if (metadata is not null)
        {
            extraAttributes.Add(CmsAttribute.CommitmentTypeIndication(metadata.CommitmentType));
            if (metadata.PolicyOid is not null && signaturePolicy is null)
            {
                extraAttributes.Add(CmsAttribute.SignaturePolicyIdentifier(metadata.PolicyOid, metadata.PolicyUri));
            }
            if (metadata.ExtraAttributes is not null)
            {
                extraAttributes.AddRange(metadata.ExtraAttributes);
            }
        }

        if (signaturePolicy is not null)
        {
            extraAttributes.Add(CmsAttribute.SignaturePolicyIdentifier(signaturePolicy));
        }

        // A signed attribute may appear once (RFC 5652 §5.3): the last one of a type wins.
        var distinct = extraAttributes
            .GroupBy(a => a.Oid, StringComparer.Ordinal)
            .Select(g => g.Last())
            .ToList();
        return distinct.Count > 0 ? distinct : null;
    }

    /// <summary>The entries of the document information dictionary with <paramref name="key"/> set to <paramref name="value"/>.</summary>
    /// <exception cref="ArgumentException">The key is empty or not a valid PDF name.</exception>
    internal static IReadOnlyDictionary<string, string> WithDocumentInfo(
        IReadOnlyDictionary<string, string>? current, string key, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(value);
        if (key.Any(c => c <= ' ' || c > '~' || "()<>[]{}/%#".Contains(c, StringComparison.Ordinal)))
        {
            throw new ArgumentException("The key must be printable ASCII without PDF delimiters.", nameof(key));
        }

        return new Dictionary<string, string>(current ?? new Dictionary<string, string>(), StringComparer.Ordinal)
        {
            [key] = value,
        };
    }

    /// <summary>The artifacts of <paramref name="artifacts"/>, each one checked.</summary>
    /// <exception cref="ArgumentException">An artifact key is not usable.</exception>
    internal static List<PdfDssArtifact> ValidatedArtifacts(IEnumerable<PdfDssArtifact> artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        var list = artifacts.ToList();
        foreach (var artifact in list)
        {
            ArgumentNullException.ThrowIfNull(artifact, nameof(artifacts));
            artifact.Validate();
        }

        return list;
    }
}
