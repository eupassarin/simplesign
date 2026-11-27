using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Signing;

/// <summary>
/// The digest an external signer (token, HSM, cloud) computes over an <see cref="ExternalSigningRequest"/>, and its OID.
/// </summary>
/// <remarks>
/// SHA-1 is accepted for one payload only, a canonical XML-DSig <c>SignedInfo</c>: the Brazilian fiscal layouts
/// (NF-e, CT-e, MDF-e and their events) mandate RSA-SHA1. CMS signed attributes are never hashed with SHA-1, and
/// whether a SHA-1 XML signature may be made at all is the signing policy's decision, taken before the request exists.
/// </remarks>
internal static class ExternalSigningDigest
{
    /// <summary>The digest of the request's payload with its hash algorithm.</summary>
    /// <param name="request">The signing request.</param>
    /// <returns>The digest.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported for this payload.</exception>
    internal static byte[] Compute(ExternalSigningRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.HashAlgorithm == HashAlgorithmName.SHA1)
        {
            RequireSha1Allowed(request);
#pragma warning disable CA5350 // SHA-1 is mandated by the SEFAZ layouts, and only for an XML SignedInfo (see the remarks)
            return SHA1.HashData(request.DataToSign.Span);
#pragma warning restore CA5350
        }

        return CryptoUtility.ComputeHash(request.DataToSign.Span, request.HashAlgorithm);
    }

    /// <summary>The OID of the request's hash algorithm.</summary>
    /// <param name="request">The signing request.</param>
    /// <returns>The digest algorithm OID.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported for this payload.</exception>
    internal static string Oid(ExternalSigningRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.HashAlgorithm == HashAlgorithmName.SHA1)
        {
            RequireSha1Allowed(request);
            return Oids.Sha1;
        }

        return CmsSignatureBuilder.GetDigestOid(request.HashAlgorithm);
    }

    /// <summary>
    /// The OID of a hash already computed by an external signer, SHA-1 included: the signer that computed it has
    /// already checked that SHA-1 was allowed (<see cref="Compute"/>).
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The digest algorithm OID.</returns>
    internal static string OidOfComputedHash(HashAlgorithmName algorithm) =>
        algorithm == HashAlgorithmName.SHA1 ? Oids.Sha1 : CmsSignatureBuilder.GetDigestOid(algorithm);

    private static void RequireSha1Allowed(ExternalSigningRequest request)
    {
        if (request.PayloadKind != ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo)
        {
            throw new NotSupportedException(
                "SHA-1 is deprecated and not supported for CMS signatures. Use SHA-256 or stronger.");
        }
    }
}
