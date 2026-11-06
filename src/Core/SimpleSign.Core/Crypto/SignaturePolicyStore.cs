using System.Security.Cryptography;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// The signature policy document carried inside a signature, or the place in a local store
/// where it is kept: the signature-policy-store unsigned attribute of CAdES
/// (ETSI EN 319 122-1 §5.2.10) and the SignaturePolicyStore unsigned property of XAdES
/// (ETSI EN 319 132-1 §5.2.10). It lets a validator read the policy offline, years later.
/// </summary>
/// <remarks>
/// The store is not covered by the signature. What protects the document is the hash in the
/// signature-policy-identifier, so a signature may carry a store only when it also declares
/// the policy with its hash.
/// </remarks>
public sealed class SignaturePolicyStore
{
    private SignaturePolicyStore(string specification, ReadOnlyMemory<byte> document, string? localUri)
    {
        Specification = specification;
        Document = document;
        LocalUri = localUri;
    }

    /// <summary>
    /// The technical specification that defines the syntax of the policy document
    /// (SPDocSpecification): an OID in dotted form, or a URI.
    /// </summary>
    public string Specification { get; }

    /// <summary>Whether <see cref="Specification"/> is an OID (dotted digits) rather than a URI.</summary>
    public bool SpecificationIsOid => IsOid(Specification);

    /// <summary>The encoded policy document; empty when the store holds a <see cref="LocalUri"/> instead.</summary>
    public ReadOnlyMemory<byte> Document { get; }

    /// <summary>The URI of the policy document in a local store; null when the store holds the <see cref="Document"/>.</summary>
    public string? LocalUri { get; }

    /// <summary>Creates a store that carries the policy document itself.</summary>
    /// <param name="specification">The OID or URI of the specification that defines the document's syntax.</param>
    /// <param name="document">The encoded policy document.</param>
    /// <exception cref="ArgumentException">The specification is empty or not ASCII, or the document is empty.</exception>
    public static SignaturePolicyStore FromDocument(string specification, ReadOnlyMemory<byte> document)
    {
        RequireAscii(specification, nameof(specification));
        if (document.IsEmpty)
        {
            throw new ArgumentException("The policy document is empty.", nameof(document));
        }

        return new SignaturePolicyStore(specification.Trim(), document.ToArray(), localUri: null);
    }

    /// <summary>Creates a store that points to the policy document in a local store.</summary>
    /// <param name="specification">The OID or URI of the specification that defines the document's syntax.</param>
    /// <param name="localUri">The URI of the document in the local store.</param>
    /// <exception cref="ArgumentException">The specification or the URI is empty or not ASCII.</exception>
    public static SignaturePolicyStore FromLocalUri(string specification, string localUri)
    {
        RequireAscii(specification, nameof(specification));
        RequireAscii(localUri, nameof(localUri));
        return new SignaturePolicyStore(specification.Trim(), ReadOnlyMemory<byte>.Empty, localUri.Trim());
    }

    /// <summary>
    /// Whether the digest of the whole stored <see cref="Document"/> is the hash the signature
    /// declares for its policy (sigPolicyHash).
    /// </summary>
    /// <remarks>
    /// Some policy formats define the hash over a part of the document (the SignPolicyInfo of an
    /// ASN.1 policy, for example). For those, <see langword="false"/> does not mean the document
    /// was altered: compare with the rule of that format.
    /// </remarks>
    /// <param name="policy">The policy the signature declares.</param>
    /// <returns>
    /// <see langword="true"/> when the digests are equal; <see langword="false"/> when they differ,
    /// when the store holds a URI, when the policy has no hash, or when its algorithm is not supported.
    /// </returns>
    public bool MatchesHash(SignaturePolicyReference policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (Document.IsEmpty || policy.Hash.IsEmpty)
        {
            return false;
        }

        byte[]? digest = policy.HashAlgorithmOid switch
        {
#pragma warning disable CA5350 // SHA-1 is what older policies declare; it is compared, not trusted
            Oids.Sha1 => SHA1.HashData(Document.Span),
#pragma warning restore CA5350
            Oids.Sha256 => SHA256.HashData(Document.Span),
            Oids.Sha384 => SHA384.HashData(Document.Span),
            Oids.Sha512 => SHA512.HashData(Document.Span),
            _ => null,
        };
        return digest is not null && CryptographicOperations.FixedTimeEquals(digest, policy.Hash.Span);
    }

    /// <summary>Whether <paramref name="value"/> is an OID in dotted form (at least two arcs of digits).</summary>
    internal static bool IsOid(string value)
    {
        string[] arcs = value.Split('.');
        return arcs.Length >= 2 && arcs.All(arc => arc.Length > 0 && arc.All(char.IsAsciiDigit));
    }

    private static void RequireAscii(string value, string parameter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameter);
        if (!value.All(char.IsAscii))
        {
            throw new ArgumentException("An OID or URI takes ASCII characters only.", parameter);
        }
    }
}
