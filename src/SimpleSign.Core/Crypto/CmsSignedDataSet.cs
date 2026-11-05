using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// A CMS SignedData with all its signers (<see cref="CmsParser.ParseAll"/>): co-signatures are
/// separate SignerInfos over the same content; countersignatures hang off each signer.
/// </summary>
public sealed class CmsSignedDataSet
{
    /// <summary>The digestAlgorithms of the SignedData.</summary>
    public IReadOnlyList<string> DigestAlgorithmOids { get; init; } = [];

    /// <summary>All certificates embedded in the SignedData.</summary>
    public IReadOnlyList<X509Certificate2> Certificates { get; init; } = [];

    /// <summary>The eContentType (id-data for ordinary signatures).</summary>
    public string? EContentTypeOid { get; init; }

    /// <summary>The encapsulated content of an attached signature (.p7m); null when detached.</summary>
    public byte[]? EncapsulatedContent { get; init; }

    /// <summary>The signers, in SignerInfo order. Each carries its own <see cref="CmsSignedData.CounterSignatures"/>.</summary>
    public IReadOnlyList<CmsSignedData> Signers { get; init; } = [];
}
